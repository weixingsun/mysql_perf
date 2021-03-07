# Performance measurement for MySQL

Bottleneck identified:
Disk usage = 100% ( disk encryption is bad for database )
```bash
PID   PRIO  USER     DISK READ  DISK WRITE    COMMAND
1059  be/4  root     0.00 B/s   25548.0 KB/s  [dmcrypt_write/2]
34630 be/0  root     0.00 B/s     148.0 KB/s  mysqld
```
# Usage

```bash
sudo ./mysql_counter.py --help
USAGE: mysql_counter [select/insert/update/delete]
```

# Measurement

```bash
$ sudo ./mysql_counter
Counting insert statements for MySQL 8115 ... Ctrl+C to End
     COUNT SQLstatements
      7403 "INSERT INTO sbtest1 (id, k, c, pad) VALUES (?, ?, ?, ?)"
Captured total 7403 insert statements in 6.286
```

```bash
$ sudo ./mysql_counter select
Counting select statements for MySQL 8115 ... Ctrl+C to End
     COUNT SQLstatements
      4661 "SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?"
      4701 "SELECT SUM(k) FROM sbtest1 WHERE id BETWEEN ? AND ?"
      4717 "SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ? ORDER BY c"
      4748 "SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ? ORDER BY c"
     47457 "SELECT c FROM sbtest1 WHERE id=?"
Captured total 66284 select statements in 4.208
```
