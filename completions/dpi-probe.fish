# fish completions for dpi-probe
complete -c dpi-probe -f
complete -c dpi-probe -s p -l port -r -d 'Target port (default 443)'
complete -c dpi-probe -l sni -r -d 'SNI to test (the one a censor might block)'
complete -c dpi-probe -l benign-sni -r -d 'Control SNI assumed un-blocked'
complete -c dpi-probe -l deep -d 'Packet-level RST-injection forensics (root)'
complete -c dpi-probe -l timeout -r -d 'Per-probe timeout in seconds'
complete -c dpi-probe -l json -d 'Machine-readable JSON output'
complete -c dpi-probe -l no-color -d 'Strip ANSI colors'
complete -c dpi-probe -s V -l version -d 'Show version and exit'
complete -c dpi-probe -s h -l help -d 'Show usage and exit'
