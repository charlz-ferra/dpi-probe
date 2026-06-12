# bash completion for dpi-probe
_dpi_probe() {
	local cur opts
	cur="${COMP_WORDS[COMP_CWORD]}"
	opts="-p --port --sni --benign-sni --deep --timeout --json --no-color -h --help -V --version"
	mapfile -t COMPREPLY < <(compgen -W "${opts}" -- "${cur}")
}
complete -F _dpi_probe dpi-probe
