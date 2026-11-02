/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Streaming implementation of the fixed BitwiseInfoV1 policy.
//!
//! Memory is proportional to the largest record, distinct address identities and
//! requested syscall history, not the number of records. Both streams are read
//! to EOF even after the diagnostic difference limit has been reached.

use std::collections::VecDeque;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::{self};
use std::ops::Range;

use super::*;

struct Records<R> {
    reader: R,
    line: String,
    line_position: usize,
    record: String,
    split_index: usize,
    index: usize,
    starts: usize,
    eof: bool,
    truncated: bool,
}

impl<R: BufRead> Records<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            line: String::new(),
            line_position: 0,
            record: String::new(),
            split_index: 0,
            index: 0,
            starts: 0,
            eof: false,
            truncated: false,
        }
    }

    fn advance(&mut self) -> io::Result<bool> {
        self.record.clear();
        if self.eof {
            return Ok(false);
        }
        loop {
            if self.line_position < self.line.len() {
                let remaining = &self.line[self.line_position..];
                if let Some(boundary) = RECORD_START.find(remaining) {
                    self.record.push_str(&remaining[..boundary.start()]);
                    self.line_position += boundary.end();
                    self.index = self.split_index;
                    self.split_index += 1;
                    self.starts += 1;
                    if self.record.trim().is_empty() {
                        self.record.clear();
                        continue;
                    }
                    return Ok(true);
                }
                self.record.push_str(remaining);
            }
            self.line.clear();
            self.line_position = 0;
            // RECORD_START cannot span a newline. Search every occurrence,
            // including timestamps inside a physical line, exactly as split().
            if self.reader.read_line(&mut self.line)? == 0 {
                self.eof = true;
                self.index = self.split_index;
                self.truncated = log_was_truncated(&self.record);
                return Ok(!self.truncated && !self.record.trim().is_empty());
            }
        }
    }
}

#[derive(Default)]
struct SavedMessage {
    index: usize,
    text: String,
    event: Option<DetLogEvent>,
}

impl SavedMessage {
    fn assign(&mut self, message: LogMessage<'_>) {
        self.index = message.index;
        self.text.clear();
        self.text.push_str(message.text);
        self.event = message.event;
    }

    fn message(&self) -> LogMessage<'_> {
        LogMessage {
            index: self.index,
            text: &self.text,
            event: self.event,
        }
    }
}

struct History {
    capacity: usize,
    completed: VecDeque<SavedMessage>,
    latest_other: SavedMessage,
    latest_is_other: bool,
}

impl History {
    fn new(requested: u64) -> Self {
        Self {
            capacity: if requested == 0 {
                0
            } else {
                usize::try_from(requested)
                    .unwrap_or(usize::MAX)
                    .saturating_add(1)
            },
            completed: VecDeque::new(),
            latest_other: SavedMessage::default(),
            latest_is_other: false,
        }
    }

    fn observe(&mut self, message: LogMessage<'_>) {
        if self.capacity == 0 || !is_detlog_syscall(&message) {
            return;
        }
        if is_detlog_syscall_result(&message) {
            let mut saved = if self.completed.len() == self.capacity {
                self.completed.pop_front().expect("full history")
            } else {
                SavedMessage::default()
            };
            saved.assign(message);
            self.completed.push_back(saved);
            self.latest_is_other = false;
        } else {
            self.latest_other.assign(message);
            self.latest_is_other = true;
        }
    }

    fn messages(&self) -> impl Iterator<Item = LogMessage<'_>> {
        self.completed
            .iter()
            .map(SavedMessage::message)
            .chain(self.latest_is_other.then(|| self.latest_other.message()))
    }
}

#[derive(Default)]
struct Counts {
    all: usize,
    detcore: usize,
    info: usize,
    deterministic: usize,
    empty_queue_kicks: usize,
    maps: usize,
    first_maps: Option<(u64, Option<u64>)>,
}

struct Side<R> {
    records: Records<R>,
    text: Range<usize>,
    event: Option<DetLogEvent>,
    addresses: HashMap<String, usize>,
    next_address: usize,
    canonical: String,
    canonicalized: bool,
    history: History,
    counts: Counts,
    last_commit: Option<(u64, Option<u64>)>,
    last_syscall: Option<u64>,
}

impl<R: BufRead> Side<R> {
    fn new(reader: R, history: u64) -> Self {
        Self {
            records: Records::new(reader),
            text: 0..0,
            event: None,
            addresses: HashMap::new(),
            next_address: 1,
            canonical: String::new(),
            canonicalized: false,
            history: History::new(history),
            counts: Counts::default(),
            last_commit: None,
            last_syscall: None,
        }
    }

    fn advance(&mut self, label: &str, options: &LogDiffOpts) -> io::Result<bool> {
        while self.records.advance().map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                io::Error::new(error.kind(), format!("{label} is not UTF-8: {error}"))
            } else {
                error
            }
        })? {
            let message = parse_log_message(self.records.index, self.records.record.trim())?;
            validate_structured_events(label, std::slice::from_ref(&message), true)?;
            self.counts.all += 1;
            if is_detcore(&message) {
                self.counts.detcore += 1;
                self.counts.deterministic += usize::from(options.includes_deterministic(&message));
            }
            if let Some(position) = commit_position(&message) {
                self.last_commit = Some(position);
            }
            if let Some(number) = finished_syscall_number(&message) {
                self.last_syscall = Some(number);
            }
            self.history.observe(message);
            if !is_info(&message) {
                continue;
            }
            self.counts.info += 1;
            self.counts.empty_queue_kicks +=
                count_empty_queue_kicks(std::slice::from_ref(&message));
            let (maps, first) = maps_read_commits(std::slice::from_ref(&message));
            self.counts.maps += maps;
            if self.counts.first_maps.is_none() {
                self.counts.first_maps = first;
            }
            // DetLogRecord::split returns a slice of this retained record. Keep
            // offsets, not a second owned copy or a self-referential borrow.
            let start = message.text.as_ptr() as usize - self.records.record.as_ptr() as usize;
            self.text = start..start + message.text.len();
            self.event = message.event;
            self.canonicalized = canonicalize_addresses_into(
                message.text,
                &mut self.addresses,
                &mut self.next_address,
                &mut self.canonical,
            );
            return Ok(true);
        }
        Ok(false)
    }

    fn message(&self) -> LogMessage<'_> {
        LogMessage {
            index: self.records.index,
            text: &self.records.record[self.text.clone()],
            event: self.event,
        }
    }

    fn normalized(&self) -> &str {
        if self.canonicalized {
            &self.canonical
        } else {
            &self.records.record[self.text.clone()]
        }
    }

    fn divergence_message(&self) -> String {
        first_divergent_message(&LogMessage {
            text: self.normalized(),
            ..self.message()
        })
    }
}

fn tail_is_truncated(file: &mut File) -> io::Result<bool> {
    let mut end = file.seek(SeekFrom::End(0))?;
    let mut bytes = [0u8; 1024];
    while end != 0 {
        let start = end.saturating_sub(bytes.len() as u64);
        file.seek(SeekFrom::Start(start))?;
        let count = (end - start) as usize;
        file.read_exact(&mut bytes[..count])?;
        if let Some(last) = bytes[..count]
            .iter()
            .rposition(|byte| !matches!(byte, b'\r' | b'\n'))
        {
            end = start + last as u64 + 1;
            break;
        }
        end = start;
    }
    let start = end.saturating_sub(TRUNCATION_MARKER.len() as u64 + 1);
    file.seek(SeekFrom::Start(start))?;
    let count = (end - start) as usize;
    file.read_exact(&mut bytes[..count])?;
    file.seek(SeekFrom::Start(0))?;
    Ok([TRUNCATION_MARKER.as_bytes(), LOG_CAP_STOP_LINE.as_bytes()]
        .iter()
        .any(|marker| {
            bytes[..count].ends_with(marker)
                && (count == marker.len() || bytes[count - marker.len() - 1] == b'\n')
        }))
}

fn count_records(mut reader: impl BufRead, label: &str) -> io::Result<usize> {
    let mut line = String::new();
    let mut count = 0;
    loop {
        line.clear();
        if reader
            .read_line(&mut line)
            .map_err(|error| io::Error::new(error.kind(), format!("{label}: {error}")))?
            == 0
        {
            return Ok(count);
        }
        count += RECORD_START.find_iter(&line).count();
    }
}

fn refusal(
    truncated: (bool, bool),
    options: &LogDiffOpts,
    writer: &mut impl Write,
) -> io::Result<LogDiffSummary> {
    // Share the existing fail-closed refusal and its typed summary. No source
    // records are fed to the materializing legacy comparator on this path.
    log_diff_summary_from_strs_with_filter(
        if truncated.0 { TRUNCATION_MARKER } else { "" },
        if truncated.1 { TRUNCATION_MARKER } else { "" },
        options,
        writer,
        |_| true,
    )
}

fn options(labels: ComparisonSideLabels, diagnostics: BitwiseInfoV1Diagnostics) -> LogDiffOpts {
    let mut options = bitwise_info_v1_options(labels);
    options.limit = diagnostics.difference_limit;
    options.syscall_history = diagnostics.syscall_history;
    options.no_color = diagnostics.no_color;
    options.print_logs = diagnostics.print_logs;
    options
}

pub(super) fn compare_files(
    left: &Path,
    right: &Path,
    labels: ComparisonSideLabels,
    diagnostics: BitwiseInfoV1Diagnostics,
    writer: &mut impl Write,
) -> io::Result<(LogDiffSummary, usize, usize)> {
    let mut left = File::open(left)?;
    let mut right = File::open(right)?;
    let truncated = (
        tail_is_truncated(&mut left)?,
        tail_is_truncated(&mut right)?,
    );
    let options = options(labels, diagnostics);
    let left = BufReader::new(left);
    let right = BufReader::new(right);
    if truncated.0 || truncated.1 {
        let left_count = count_records(left, &options.side_labels.left)?;
        let right_count = count_records(right, &options.side_labels.right)?;
        return Ok((
            refusal(truncated, &options, writer)?,
            left_count,
            right_count,
        ));
    }
    compare_readers(left, right, &options, writer)
}

pub(super) fn compare_strs(
    left: &str,
    right: &str,
    labels: ComparisonSideLabels,
    diagnostics: BitwiseInfoV1Diagnostics,
    writer: &mut impl Write,
) -> io::Result<(LogDiffSummary, usize, usize)> {
    let options = options(labels, diagnostics);
    let truncated = (log_was_truncated(left), log_was_truncated(right));
    if truncated.0 || truncated.1 {
        return Ok((
            refusal(truncated, &options, writer)?,
            record_count(left),
            record_count(right),
        ));
    }
    compare_readers(Cursor::new(left), Cursor::new(right), &options, writer)
}

fn compare_readers(
    left: impl BufRead,
    right: impl BufRead,
    options: &LogDiffOpts,
    writer: &mut impl Write,
) -> io::Result<(LogDiffSummary, usize, usize)> {
    let mut left = Side::new(left, options.syscall_history);
    let mut right = Side::new(right, options.syscall_history);
    let mut summary = LogDiffSummary {
        diff_found: false,
        compared_left: 0,
        compared_right: 0,
        first_divergent_scheduler_turn: None,
        first_divergent_virtual_nanoseconds: None,
        first_divergent_record: None,
        first_divergent_record_positions: None,
        matched_prefix_messages: Some(0),
        first_divergent_syscall: None,
        first_divergent_left_message: None,
        first_divergent_right_message: None,
        refusal_reason: None,
    };
    let mut rendered = 0u64;
    let mut elided = false;
    let mut extra_tail = VecDeque::<String>::new();
    writeln!(
        writer,
        "Canonicalizing host addresses (ordinal by first appearance); comparing everything else exactly..."
    )?;
    writeln!(writer, "  Comparing INFO messages...\n")?;
    loop {
        let has_left = left.advance(&options.side_labels.left, options)?;
        let has_right = right.advance(&options.side_labels.right, options)?;
        if !has_left && !has_right {
            break;
        }
        if options.print_logs {
            for (label, present, record, text) in [
                (
                    options.side_labels.left.as_str(),
                    has_left,
                    left.records.index,
                    if has_left { left.normalized() } else { "" },
                ),
                (
                    options.side_labels.right.as_str(),
                    has_right,
                    right.records.index,
                    if has_right { right.normalized() } else { "" },
                ),
            ] {
                if present {
                    writeln!(writer, "{label} canonical INFO record {record}:\n{text}")?;
                }
            }
        }
        if has_left && has_right && left.normalized() == right.normalized() {
            if !summary.diff_found {
                *summary
                    .matched_prefix_messages
                    .as_mut()
                    .expect("compared prefix") += 1;
            }
            continue;
        }
        if !summary.diff_found {
            let position = has_left
                .then_some(left.last_commit)
                .flatten()
                .or_else(|| has_right.then_some(right.last_commit).flatten());
            let left_index = has_left.then_some(left.records.index);
            let right_index = has_right.then_some(right.records.index);
            summary.diff_found = true;
            summary.first_divergent_scheduler_turn = position.map(|value| value.0);
            summary.first_divergent_virtual_nanoseconds = position.and_then(|value| value.1);
            summary.first_divergent_record = left_index.or(right_index);
            summary.first_divergent_record_positions = Some((left_index, right_index));
            summary.first_divergent_syscall = has_left
                .then_some(left.last_syscall)
                .flatten()
                .or_else(|| has_right.then_some(right.last_syscall).flatten());
            summary.first_divergent_left_message = has_left.then(|| left.divergence_message());
            summary.first_divergent_right_message = has_right.then(|| right.divergence_message());
        }
        if !has_left || !has_right {
            let mut saved = if extra_tail.len() == 10 {
                extra_tail.pop_front().expect("full tail")
            } else {
                String::new()
            };
            saved.clear();
            saved.push_str(if has_left {
                left.normalized()
            } else {
                right.normalized()
            });
            extra_tail.push_back(saved);
            continue;
        }
        if options.limit != 0 && rendered >= options.limit {
            if !elided {
                writeln!(
                    writer,
                    "More than {} differences, eliding the rest...",
                    options.limit
                )?;
                elided = true;
            }
            continue;
        }
        write!(
            writer,
            "(INFO) Mismatch at log messages {} ({}) and {} ({}): {}",
            left.records.index,
            options.side_labels.left,
            right.records.index,
            options.side_labels.right,
            Comparison::new(options.no_color, left.normalized(), right.normalized())
        )?;
        write!(
            writer,
            "(INFO) Original entries before normalization: {}",
            Comparison::new(options.no_color, left.message().text, right.message().text)
        )?;
        let left_history: Vec<_> = left.history.messages().collect();
        let right_history: Vec<_> = right.history.messages().collect();
        write_syscall_context(
            writer,
            left.records.index,
            right.records.index,
            &left_history,
            &right_history,
            &options.side_labels,
            options.syscall_history,
        )?;
        rendered += 1;
    }
    let record_counts = (left.records.starts, right.records.starts);
    let truncated = (left.records.truncated, right.records.truncated);
    if truncated.0 || truncated.1 {
        return Ok((
            refusal(truncated, options, writer)?,
            record_counts.0,
            record_counts.1,
        ));
    }
    summary.compared_left = left.counts.info;
    summary.compared_right = right.counts.info;
    writeln!(
        writer,
        "Logs contain {} | {} messages total",
        left.counts.all, right.counts.all
    )?;
    writeln!(
        writer,
        "Logs contain {} | {} detcore-specific messages",
        left.counts.detcore, right.counts.detcore
    )?;
    writeln!(
        writer,
        "Logs contain {} | {} INFO messages",
        left.counts.info, right.counts.info
    )?;
    writeln!(
        writer,
        "Logs contain {} | {} DETLOG & scheduler COMMIT messages",
        left.counts.deterministic, right.counts.deterministic
    )?;
    if left.counts.info != right.counts.info {
        let (longer, shorter) = if left.counts.info > right.counts.info {
            (&options.side_labels.left, &options.side_labels.right)
        } else {
            (&options.side_labels.right, &options.side_labels.left)
        };
        writeln!(
            writer,
            "{} contains {} extra messages not matched in {}. Displaying up to 10:",
            sentence_case_label(longer),
            left.counts.info.abs_diff(right.counts.info),
            shorter
        )?;
        for message in extra_tail {
            writeln!(writer, "{message}")?;
        }
    }
    if summary.diff_found {
        writeln!(writer, "Done processing logs, differences found.")?;
    } else if summary.compared_left == 0 && summary.compared_right == 0 {
        writeln!(
            writer,
            "Done processing logs, but ZERO INFO messages were selected on either side: nothing was compared (no-result, not a match)."
        )?;
    } else {
        writeln!(
            writer,
            "Done processing logs, no substantive differences found ({} | {} INFO messages compared).",
            summary.compared_left, summary.compared_right
        )?;
        writeln!(
            writer,
            "Logs contain {} | {} scheduler empty-run-queue kick messages",
            left.counts.empty_queue_kicks, right.counts.empty_queue_kicks
        )?;
        let positions = if left.counts.first_maps.is_none() && right.counts.first_maps.is_none() {
            String::new()
        } else {
            format!(
                " ({} {}, {} {})",
                options.side_labels.left,
                describe_maps_commit(left.counts.first_maps),
                options.side_labels.right,
                describe_maps_commit(right.counts.first_maps)
            )
        };
        writeln!(
            writer,
            "Logs contain {} | {} scheduler COMMIT records reading /proc/self/maps{positions}",
            left.counts.maps, right.counts.maps
        )?;
    }
    Ok((summary, record_counts.0, record_counts.1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(second: usize, level: &str, body: &str, event: Option<DetLogEvent>) -> String {
        let suffix = event.map(crate::detlog::record_suffix).unwrap_or_default();
        format!("2026-11-01T00:00:{second:02}.000000Z {level} detcore: {body}{suffix}\n")
    }

    fn comparison_options() -> LogDiffOpts {
        bitwise_info_v1_options(ComparisonSideLabels::new("left", "right"))
    }

    fn check_equivalence(left: &str, right: &str) {
        let options = comparison_options();
        let expected =
            log_diff_summary_from_strs_with_filter(left, right, &options, &mut io::sink(), |_| {
                true
            })
            .unwrap();
        for capacity in [1, 7, 64, 4096] {
            let (actual, left_count, right_count) = compare_readers(
                BufReader::with_capacity(capacity, Cursor::new(left)),
                BufReader::with_capacity(capacity, Cursor::new(right)),
                &options,
                &mut io::sink(),
            )
            .unwrap();
            assert_eq!(actual, expected, "reader capacity {capacity}");
            assert_eq!(
                (left_count, right_count),
                (record_count(left), record_count(right))
            );
        }
    }

    #[test]
    fn preserves_address_identity_aliasing_and_multiline_records() {
        let left = format!(
            "{}{}",
            record(
                1,
                "INFO",
                "first <hostaddr 0x111>\nUTF-8 café 文\nINFO continuation",
                None
            ),
            record(
                2,
                "INFO",
                "again <hostaddr 0x111>, next <hostaddr 0x222>",
                None
            )
        );
        let shifted = left.replace("0x111", "0xaaa").replace("0x222", "0xbbb");
        check_equivalence(&left, &shifted);
        check_equivalence(
            &left,
            &shifted.replace("again <hostaddr 0xaaa>", "again <hostaddr 0xccc>"),
        );
        check_equivalence(
            &left,
            &format!("{shifted}{}", record(3, "INFO", "additional", None)),
        );
        check_equivalence(
            &left,
            &record(
                1,
                "INFO",
                "first <hostaddr 0xaaa>\nUTF-8 café 文\nINFO continuation",
                None,
            ),
        );
    }

    #[test]
    fn preserves_unanchored_record_boundaries_and_unframed_prefixes() {
        let cases = [
            String::new(),
            "\r\n\t  ".to_owned(),
            "INFO unframed prefix\n".to_owned(),
            format!("INFO unframed prefix\n{}", record(1, "INFO", "next", None)),
            record(
                1,
                "INFO",
                "embedded 2026-11-01T01:02:03.000Z INFO nested record",
                None,
            ),
            "Apr 09 06:08:01.100  INFO old format\r\n\r\n".to_owned(),
            "2026-11-01T00:00:01x123Z INFO wildcard separator\n".to_owned(),
            format!(
                "{}{}",
                record(1, "DEBUG", "not selected <hostaddr 0x111>", None),
                record(2, "INFO", "selected <hostaddr 0x222>", None)
            ),
        ];
        for input in &cases {
            check_equivalence(input, input);
            check_equivalence(
                input,
                &format!("{input}{}", record(3, "INFO", "extra", None)),
            );
        }
    }

    #[test]
    fn preserves_all_divergence_coordinates_and_exhausted_side_precedence() {
        let commit = record(
            1,
            "INFO",
            "COMMIT turn 17 at time 123",
            Some(DetLogEvent::SchedulerCommit {
                scheduler_turn: 17,
                virtual_nanoseconds: 123,
                internal_io_poll: false,
                runtime_maps_read: false,
            }),
        );
        let syscall = record(
            2,
            "INFO",
            "DETLOG [syscall] finish syscall #37: write = Ok(1)",
            Some(DetLogEvent::SyscallResult {
                finished_syscall_number: 37,
            }),
        );
        let left = format!(
            "{commit}{syscall}{}",
            record(3, "INFO", "DETLOG value=1", Some(DetLogEvent::Other))
        );
        let right = left.replace("value=1", "value=2");
        check_equivalence(&left, &right);
        check_equivalence(
            &left,
            &format!("{left}{}", record(4, "INFO", "extra", None)),
        );
        let trailing_debug = record(
            5,
            "DEBUG",
            "COMMIT turn 99 at time 999",
            Some(DetLogEvent::SchedulerCommit {
                scheduler_turn: 99,
                virtual_nanoseconds: 999,
                internal_io_poll: false,
                runtime_maps_read: false,
            }),
        );
        check_equivalence(
            &format!("{left}{trailing_debug}"),
            &format!("{left}{}", record(6, "INFO", "extra", None)),
        );
    }

    #[test]
    fn diagnostic_limits_do_not_skip_tail_validation_or_change_the_verdict() {
        let left = (0..12)
            .map(|i| record(i, "INFO", "left", None))
            .collect::<String>();
        let right = (0..12)
            .map(|i| record(i, "INFO", "right", None))
            .collect::<String>();
        let expected = compare_strs(
            &left,
            &right,
            comparison_options().side_labels,
            BitwiseInfoV1Diagnostics::default(),
            &mut io::sink(),
        )
        .unwrap();
        for limit in [0, 1, 20] {
            for print_logs in [false, true] {
                let actual = compare_strs(
                    &left,
                    &right,
                    comparison_options().side_labels,
                    BitwiseInfoV1Diagnostics {
                        difference_limit: limit,
                        print_logs,
                        syscall_history: 0,
                        no_color: true,
                    },
                    &mut io::sink(),
                )
                .unwrap();
                assert_eq!(actual, expected);
            }
        }
        let invalid_tail = format!(
            "{right}{}",
            record(13, "DEBUG", "COMMIT turn 5 at time 6", None)
        );
        let result = compare_strs(
            &left,
            &invalid_tail,
            comparison_options().side_labels,
            BitwiseInfoV1Diagnostics {
                difference_limit: 1,
                ..Default::default()
            },
            &mut io::sink(),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn late_syscall_and_history_state_match_materialized_diagnostics() {
        let mut left = String::new();
        for n in 1..9 {
            left.push_str(&record(
                n,
                "INFO",
                &format!("DETLOG [syscall] finish syscall #{n}: read = Ok(1)"),
                Some(DetLogEvent::SyscallResult {
                    finished_syscall_number: n as u64,
                }),
            ));
        }
        left.push_str(&record(
            10,
            "INFO",
            "DETLOG [syscall] inbound syscall: write(1)",
            Some(DetLogEvent::Syscall),
        ));
        left.push_str(&record(11, "INFO", "outcome=1", None));
        let right = left.replace("outcome=1", "outcome=2");
        check_equivalence(&left, &right);
        let options = comparison_options();
        let mut original_output = Vec::new();
        log_diff_summary_from_strs_with_filter(
            &left,
            &right,
            &options,
            &mut original_output,
            |_| true,
        )
        .unwrap();
        let mut streamed_output = Vec::new();
        compare_readers(
            Cursor::new(&left),
            Cursor::new(&right),
            &options,
            &mut streamed_output,
        )
        .unwrap();
        let relevant = |bytes: Vec<u8>| {
            String::from_utf8(bytes)
                .unwrap()
                .lines()
                .filter(|line| line.starts_with("  ") && line.contains("syscall"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(relevant(streamed_output), relevant(original_output));
    }

    #[test]
    fn file_tail_checks_preserve_truncation_and_utf8_refusals() {
        let prefix = record(1, "INFO", "kept", None);
        let endings = [
            format!("\n{TRUNCATION_MARKER}\n"),
            format!("\n{LOG_CAP_STOP_LINE}{}", "\r\n".repeat(1500)),
            format!("quoted {TRUNCATION_MARKER}\n"),
            format!("\n{TRUNCATION_MARKER} trailing bytes\n"),
        ];
        for ending in endings {
            let input = format!("{prefix}{ending}");
            let left = NamedTempFile::new().unwrap();
            let right = NamedTempFile::new().unwrap();
            std::fs::write(left.path(), &input).unwrap();
            std::fs::write(right.path(), &input).unwrap();
            let expected = log_diff_summary_from_strs_with_filter(
                &input,
                &input,
                &comparison_options(),
                &mut io::sink(),
                |_| true,
            )
            .unwrap();
            let (actual, a, b) = compare_files(
                left.path(),
                right.path(),
                comparison_options().side_labels,
                BitwiseInfoV1Diagnostics::default(),
                &mut io::sink(),
            )
            .unwrap();
            assert_eq!(actual, expected);
            assert_eq!((a, b), (record_count(&input), record_count(&input)));
            let mut invalid = input.into_bytes();
            invalid.insert(0, 0xff);
            std::fs::write(left.path(), invalid).unwrap();
            assert_eq!(
                compare_files(
                    left.path(),
                    right.path(),
                    comparison_options().side_labels,
                    BitwiseInfoV1Diagnostics::default(),
                    &mut io::sink()
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
