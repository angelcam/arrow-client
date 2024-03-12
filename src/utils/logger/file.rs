// Copyright 2016 click2stream, Inc.
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

//! file logger definitions.

use std::fs;
use std::io;

use std::fmt::Arguments;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::utils::logger::{Logger, Severity};

/// Internal logger implementation.
struct InternalFileLogger {
    level: Severity,
    path: PathBuf,
    file: File,
    written: usize,
    limit: usize,
    rotations: usize,
}

impl InternalFileLogger {
    /// Write a given line into the underlaying file and rotate as necessary.
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.write(line.as_bytes())
    }

    /// Write given data into the underlaying file and rotate as necessary.
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if (self.written + data.len()) > self.limit {
            self.rotate()?;
        }

        self.file.write_all(data)?;

        self.written += data.len();

        self.file.flush()
    }

    /// Rotate the log files.
    fn rotate(&mut self) -> io::Result<()> {
        for i in 0..self.rotations - 1 {
            let mut from = self.path.as_os_str().to_os_string();
            let mut to = self.path.as_os_str().to_os_string();

            from.push(format!(".{}", self.rotations - i - 1));
            to.push(format!(".{}", self.rotations - i));

            let from = PathBuf::from(from);
            let to = PathBuf::from(to);

            if from.exists() {
                fs::rename(&from, &to)?;
            }
        }

        if self.rotations > 0 {
            let mut to = self.path.as_os_str().to_os_string();

            to.push(".1");

            let to = PathBuf::from(to);

            fs::rename(&self.path, to)?;
        }

        self.file = File::create(&self.path)?;

        self.written = 0;

        Ok(())
    }
}

impl Logger for InternalFileLogger {
    fn log(&mut self, file: &str, line: u32, s: Severity, msg: Arguments) {
        let t = time::strftime("%F %T", &time::now()).unwrap();

        let severity = match s {
            Severity::DEBUG => "DEBUG",
            Severity::INFO => "INFO",
            Severity::WARN => "WARNING",
            Severity::ERROR => "ERROR",
        };

        if s >= self.level {
            self.write_line(&format!(
                "{} {:<7} [{}:{}] {}\n",
                t, severity, file, line, msg
            ))
            .unwrap();
        }
    }

    fn set_level(&mut self, s: Severity) {
        self.level = s;
    }

    fn get_level(&self) -> Severity {
        self.level
    }
}

/// File logger.
#[derive(Clone)]
pub struct FileLogger {
    shared: Arc<Mutex<InternalFileLogger>>,
}

impl FileLogger {
    /// Create a new file logger with a given file size limit, given number of backup files
    /// (rotations) and with log level set to INFO.
    pub fn new<P>(path: P, limit: usize, rotations: usize) -> io::Result<Self>
    where
        PathBuf: From<P>,
    {
        let path = PathBuf::from(path);

        let written = match path.metadata() {
            Ok(metadata) => metadata.len(),
            Err(_) => 0,
        };

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        let logger = InternalFileLogger {
            level: Severity::INFO,
            path,
            file,
            written: written as usize,
            limit,
            rotations,
        };

        let logger = Self {
            shared: Arc::new(Mutex::new(logger)),
        };

        Ok(logger)
    }
}

impl Logger for FileLogger {
    fn log(&mut self, file: &str, line: u32, s: Severity, msg: Arguments) {
        self.shared.lock().unwrap().log(file, line, s, msg)
    }

    fn set_level(&mut self, s: Severity) {
        self.shared.lock().unwrap().set_level(s)
    }

    fn get_level(&self) -> Severity {
        self.shared.lock().unwrap().get_level()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::ffi::OsStr;
    use std::fs;
    use std::path::Path;

    use crate::utils::logger::Logger;

    fn file_exists<P: AsRef<OsStr> + ?Sized>(file: &P) -> bool {
        Path::new(file).exists()
    }

    fn remove_file<P: AsRef<Path>>(file: P) {
        fs::remove_file(file).ok();
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

        let mut logger = FileLogger::new("testlog", 100, 5).unwrap();

        log_debug!(logger, "foo");

        log_info!(logger, "foo");

        assert!(file_exists("testlog"));
        assert!(!file_exists("testlog.1"));

        log_warn!(logger, "foo");

        assert!(file_exists("testlog.1"));
        assert!(!file_exists("testlog.2"));

        log_warn!(logger, "foo");

        assert!(file_exists("testlog.2"));
        assert!(!file_exists("testlog.3"));

        log_warn!(logger, "foo");

        assert!(file_exists("testlog.3"));
        assert!(!file_exists("testlog.4"));

        log_warn!(logger, "foo");

        assert!(file_exists("testlog.4"));
        assert!(!file_exists("testlog.5"));

        log_warn!(logger, "foo");

        assert!(file_exists("testlog.5"));
        assert!(!file_exists("testlog.6"));

        log_warn!(logger, "foo");

        assert!(file_exists("testlog.5"));
        assert!(!file_exists("testlog.6"));

        remove_files();
    }
}
