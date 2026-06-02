# bash completion for dmrcrack / dmrcrack-cli
# Install: copy to /usr/share/bash-completion/completions/dmrcrack
#          (the Debian package installs it there automatically)

_dmrcrack() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--bin --start --end --threads --gpu-pct --samples --key \
          --wordlist --potfile --json --benchmark --no-resume --help -h"

    case "$prev" in
        --bin|--wordlist|--potfile)
            # complete file paths
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        --start|--end|--key)
            # 40-bit hex value — no completion candidates
            return 0
            ;;
        --threads|--gpu-pct|--samples)
            # numeric argument — no completion candidates
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return 0
    fi

    # default: complete .bin files
    COMPREPLY=( $(compgen -f -X '!*.bin' -- "$cur") )
    return 0
}

complete -F _dmrcrack dmrcrack
complete -F _dmrcrack dmrcrack-cli
