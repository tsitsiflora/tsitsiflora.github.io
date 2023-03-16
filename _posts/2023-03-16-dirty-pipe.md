---
layout: post
title:  "Dirty Pipe Vulnerability: An analysis"
date:   2023-03-16 12:00:04 +0200
categories: security
---

## This is an analysis of the [Dirty Pipe Vulnerability](https://dirtypipe.cm4all.com/)

The Dirty Pipe vulnerability is a Linux kernel vulnerability found in version 5.8 and up. It is much like the [Dirt COW](https://tsitsiflora.github.io/dirty-cow/) vulnerability that I have written about previously and it allows overwriting of data in arbitrary read-only files. This makes it a priviledge escalation vulnerability because unpriviledged processes can inject code into root proceses. 

## Technical things to know

### 1. Paging

Paging is a memory management scheme where a computer stores and retrieves data from secondary storage for use in main memory. Secondary storage refers to the hard disk and main memory refers to RAM(Random access memory).

In this scheme the operating system retrives data from secondary storage in same size blocks called pages. This is done because RAM is way faster than the hard disk, and so the data access speeds of the RAM can cope up with the CPU speed. 

Pages are usually 4KB in size. Main memory is divide into equal chunks called frames. So when the CPU needs to compute a process, the whole process is divided into equal chunks known as pages and then loaded into the main memory.

### 2. Page Caching

A page cache, sometimes called a disk cache is a transparent cache for the pages originating from the hard disk. The OS keeps a page cache in unused portions of the main memory resulting in quicker access to the contents of the cache pages and overall performance improvements. 

This copy in the page cache remains for some time, from where it can be used when needed, avoiding expensive hard disk I/O, until the kernel decides it has better use for that memory. A page cache is implemented with the paging memory management and is mostly transparent to applications. Page caching is advantegeous in bothe read and write operations:

Reading: File blocks are written to the page cache not just during writing, but also when reading files. If a file is read twice, the second access will be much quicker as it is being read from the page cache in memory, not from the hard disk.

Writing: If data is written, it is first written to the page cache and managed as one of it's dirty pages. Dirty means the data is stored in the page cache, but needs to be written to the underlying storage first. The contents of these dirty pages is periodically transferred to the underlying storage device. 

### 3. Pipes

According to the [man pages: ](https://man7.org/linux/man-pages/man7/pipe.7.html)

    Pipes and FIFOs (also known as named pipes) provide a
    unidirectional interprocess communication channel.  A pipe has a read end and a write end.  Data written to the write end of a pipe can be read from the read end of the pipe.

Data moves from left to right through pipes and therefore pipes are unidirectional. A pipe connects two or more processes, programs or commands for a limited time. Pipes are used for sending the output of one process, program, or command to another process, program, or command for additional processing.

Here is an example:

    ls -al | grep ".txt"

When trying to find text files in a directory, you can list all the files in the directory, then pass that output to grep as input. Grep will take that input and find files with `.txt` then return those to stdout. So basically, the pipe takes the output of a process and writes it into a pipe from where it can be read as an input for the next process in the chronology.

### 4. Pipe flags

Flags specify the status and permissions for the data in the pipe. One of the key flags that plays a role in this vulnerability is the `PIPE_BUF_FLAG_CAN_MERGE`. This flag signifies that the data buffer inside the pipe can be merged, i.e, this flag notifies the kernel that the changes which are written to the page cache pointed to by the pipe shall be written back to the file that the page is sourced from.

### 5. Quick Detour: Page splicing

`splice()` is a system call that moves data between a file descriptor and a pipe, without requiring the data to cross the user-mode/kernel-mode address space boundary, which results in better performance. On a higher level, splice() does this by not moving the actual data into the pipe, but the whereabouts or the reference to that data into the pipe. Now the pipe contains the reference to the location of the page cache in memory where the desired data is stored, rather than having the actual data itself. 

Basically, page slicing is a performance trick to merge data between different pipe pages without actually rewriting data to memory.

### Back to the PIPE_BUF_FLAG_CAN_MERGE Flag

For a page to be eligible to be merged, the PIPE_BUF_FLAG_CAN_MERGE flag must be set on the page cache. This flag is set by the kernel when the page becomes full. If the page cache is then emptied, the PIPE_BUF_FLAG_CAN_MERGE flag is retained. This then becomes an issue as you’ll soon see.

## Fitting it all together

In the [disclosure post](https://dirtypipe.cm4all.com/), Max Kellman describes how they stumbled upon the vulnerability, all the tests he did to confirm it is a kernel vulnerability and also published an exploit. 

Here is how an attacker can exploit the CVE-2022-0847:

They first need to access a shell on a system through some means. This can be using a normal user account or a service account. Next the attacker targets a file that they would like to write to, and they should have read privileges to that file. For example, password and configuration files in `/etc`. The attacker runs a program to open a pipe, fills page caches with random bytes so that the PIPE_BUF_FLAG_CAN_MERGE flag is set. They then empty and replace it with the data they want to overwrite with.  The PIPE_BUF_FLAG_CAN_MERGE flag causes the new data to be merged back into the original target file and circumvents the read-only restriction.

## Exploit code analysis

1. The exploit reads the target file (which has read permission) so that it gets cached in the page cache.
2. Then, the exploit creates a pipe in a special way such that it has the PIPE_BUF_FLAG_CAN_MERGE flag set.
3. Next, the exploit uses the splice() system call to make the pipe point to the location of the page cache where the desired data of the file is cached.
4. Finally, we write arbitrary data into the pipe. This data will overwrite the cached file page & because PIPE_BUF_FLAG_CAN_MERGE is set, it ultimately overwrites the file on the disk, thus accomplishing our task.

The exploit that I am using can be found [here](https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit).