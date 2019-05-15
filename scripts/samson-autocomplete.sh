#/usr/bin/env bash
_samson_completions()
{
    if [ "${#COMP_WORDS[@]}" == "2" ]; then
        local reply=($(compgen -W "load hash pki" "${COMP_WORDS[1]}"))
        COMPREPLY=("${reply[@]}")
        return
    fi

    if [ "${COMP_WORDS[1]}" == "hash" ]; then
        local reply=($(compgen -W "--args blake2b blake2s keccak md4 md5 ripemd160 sha1 sha224 sha256 sha384 sha512 sha3_224 sha3_256 sha3_384 sha3_512 shake128 shake256 whirlpool" "${COMP_WORDS[2]}"))
        COMPREPLY=("${reply[@]}")
        return
    fi

    if [ "${COMP_WORDS[1]}" == "pki" ]; then
        if [[ "${COMP_WORDS[-2]}" == "pki" ]]; then
            local reply=($(compgen -W "generate parse" "${COMP_WORDS[2]}"))
        elif [[ "${COMP_WORDS[-2]}" == "generate" || "${COMP_WORDS[-2]}" == "parse" ]]; then
        #if [ ${#COMP_WORDS[@]} -eq 4 ]; then
            local reply=($(compgen -W "rsa dsa ecdsa eddsa auto" "${COMP_WORDS[3]}"))
        elif [ ${#COMP_WORDS[@]} -gt 4 ]; then
            local reply=($(compgen -W "filename --args --pub --encoding --encoding-args" "${COMP_WORDS[5]}"))
        fi
        
        COMPREPLY=("${reply[@]}")
        return
    fi
}

complete -F _samson_completions samson
complete -F _samson_completions samson-py