// Copyright 2025 Angelcam, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    fmt::Write as _,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::Mutex,
};

use log::{Level, Log, Metadata, Record};

use crate::utils::logger::LogTimeFormatter;

/// File logger.
pub struct FileLogger {
    inner: Mutex<InternalFileLogger>,
}

impl FileLogger {
    /// Create a new file logger with a given file size limit and given number
    /// of backup files (rotations).
    pub fn new<P>(path: P, limit: usize, rotations: usize) -> io::Result<Self>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();

        let inner = InternalFileLogger::new(path, limit, rotations)?;

        let res = Self {
            inner: Mutex::new(inner),
        };

        Ok(res)
    }
}

impl Log for FileLogger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let _ = self.inner.lock().unwrap().log(record);
    }

    fn flush(&self) {
        let _ = self.inner.lock().unwrap().flush();
    }
}

/// Internal logger implementation.
struct InternalFileLogger {
    file: LogFile,
    buffer: String,
}

impl InternalFileLogger {
    /// Create a new internal file logger.
    fn new(path: PathBuf, limit: usize, rotations: usize) -> io::Result<Self> {
        let file = LogFile::new(path, limit, rotations)?;

        let res = Self {
            file,
            buffer: String::new(),
        };

        Ok(res)
    }

    /// Log a given record.
    fn log(&mut self, record: &Record) -> io::Result<()> {
        let file = record.file().unwrap_or("-");
        let line = record.line().unwrap_or(0);

        let args = record.args();

        let level = match record.level() {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARNING",
            Level::Error => "ERROR",
        };

        let mut time_formatter = LogTimeFormatter::new();

        let t = time_formatter.format();

        self.buffer.clear();

        let _ = writeln!(self.buffer, "{t} {level:<7} [{file}:{line}] {args}");

        self.file.write(self.buffer.as_bytes())
    }

    /// Flush the logger.
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Log file with rotation support.
struct LogFile {
    path: PathBuf,
    file: File,
    written: usize,
    limit: usize,
    rotations: usize,
}

impl LogFile {
    /// Create a new log file.
    fn new(path: PathBuf, limit: usize, rotations: usize) -> io::Result<Self> {
        let written = match path.metadata() {
            Ok(metadata) => metadata.len(),
            Err(_) => 0,
        };

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        let res = Self {
            path,
            file,
            written: written as usize,
            limit,
            rotations,
        };

        Ok(res)
    }

    /// Write given data into the underlying file and rotate as necessary.
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if (self.written + data.len()) > self.limit {
            eprintln!("rotating log file...");

            self.flush()?;
            self.rotate()?;
        }

        self.file.write_all(data)?;

        self.written += data.len();

        eprintln!("written bytes: {}", self.written);

        Ok(())
    }

    /// Flush the log file.
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    /// Rotate the log files.
    fn rotate(&mut self) -> io::Result<()> {
        let base_path = self.path.display();

        for i in 0..self.rotations - 1 {
            let from = PathBuf::from(format!("{}.{}", base_path, self.rotations - i - 1));

            if from.exists() {
                std::fs::rename(from, format!("{}.{}", base_path, self.rotations - i))?;
            }
        }

        if self.rotations > 0 {
            std::fs::rename(&self.path, format!("{base_path}.1"))?;
        }

        self.file = File::create(&self.path)?;

        self.written = 0;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use log::{Level, Log, Record};

    use super::FileLogger;

    fn file_exists<P>(file: P) -> bool
    where
        P: AsRef<Path>,
    {
        file.as_ref().exists()
    }

    fn remove_file<P>(file: P)
    where
        P: AsRef<Path>,
    {
        let _ = std::fs::remove_file(file);
    }

    fn remove_files() {
        remove_file("testlog");
        remove_file("testlog.1");
        remove_file("testlog.2");
        remove_file("testlog.3");
        remove_file("testlog.4");
        remove_file("testlog.5");
    }

    #[test]
    fn test_file_logger() {
        remove_files();

        let record = Record::builder()
            .args(format_args!("foo"))
            .level(Level::Warn)
            .file(Some("test.rs"))
            .line(Some(42))
            .build();

        let logger = FileLogger::new("testlog", 100, 5).unwrap();

        logger.log(&record);
        logger.log(&record);

        assert!(file_exists("testlog"));
        assert!(!file_exists("testlog.1"));

        logger.log(&record);
        logger.log(&record);

        assert!(file_exists("testlog.1"));
        assert!(!file_exists("testlog.2"));

        logger.log(&record);
        logger.log(&record);

        assert!(file_exists("testlog.2"));
        assert!(!file_exists("testlog.3"));

        logger.log(&record);
        logger.log(&record);

        assert!(file_exists("testlog.3"));
        assert!(!file_exists("testlog.4"));

        logger.log(&record);
        logger.log(&record);

        assert!(file_exists("testlog.4"));
        assert!(!file_exists("testlog.5"));

        logger.log(&record);
        logger.log(&record);

        assert!(file_exists("testlog.5"));
        assert!(!file_exists("testlog.6"));

        logger.log(&record);
        logger.log(&record);

        assert!(file_exists("testlog.5"));
        assert!(!file_exists("testlog.6"));

        remove_files();
    }
}
