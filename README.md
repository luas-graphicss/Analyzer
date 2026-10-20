# ByteGuard Analyzer

[Leia em português](README.pt-BR.md)

ByteGuard is a static file analyzer written in Python. You hand it a file and it tells you whether there is anything suspicious inside, without ever running that file. It works completely offline and uses only the Python standard library, so there is nothing extra to install.

It opens containers like compressed archives and PDF and XML documents, goes through their contents looking for signs of risk and then gives you a report with every finding and its severity. Everything is limited on purpose. There are caps on file size, on how deep it goes into nested containers, on the decompression ratio, on the number of members, on total bytes and on processing time, and the analysis runs in a separate worker with a memory limit on systems that support it. That way a malicious file made to blow up in size or hang the analyzer does not take the machine down with it.

The report can come out as plain text, JSON or SARIF 2.1.0, which plugs into security tools and CI pipelines. You can also compare the file against a SHA-256 from a trusted source and use a blocklist of known hashes. The program exits with code 1 when the risk reaches the level you chose, which is high by default.

There is also a simple desktop interface for anyone who prefers not to use the terminal.

## How to use

You need Python 3.11 or newer. The easiest way is to run python run.py, which opens the desktop interface. To use it from the terminal, install it with pip from the repository folder and the byteguard command becomes available. Then run byteguard followed by the path of the file you want to check. byteguard --help lists every option, like the report format, the output file and all the limits. The desktop interface also opens with byteguard --gui or with the byteguard-desktop command.

## Development time

ByteGuard was built in two hours.

## License

GNU General Public License version 3. The full text is in the LICENSE file.
