#!/usr/bin/env bash

parseargs() {
    notquote="-"
    str=$1
    declare -a args=()
    s=""

    # Strip leading space, then trailing space, then end with space.
    str="${str## }"
    str="${str%% }"
    str+=" "

    last_quote="${notquote}"
    is_space=""
    n=$((${#str} - 1))

    for ((i = 0; i <= $n; i += 1)); do
        c="${str:$i:1}"

        # If we're ending a quote, break out and skip this character
        if [ "$c" == "$last_quote" ]; then
            last_quote=$notquote
            continue
        fi

        # If we're in a quote, count this character
        if [ "$last_quote" != "$notquote" ]; then
            s+=$c
            continue
        fi

        # If we encounter a quote, enter it and skip this character
        if [ "$c" == "'" ] || [ "$c" == '"' ]; then
            is_space=""
            last_quote=$c
            continue
        fi

        # If it's a space, store the string
        re="[[:space:]]+" # must be used as a var, not a literal
        if [[ $c =~ $re ]]; then
            if [ "0" == "$i" ] || [ -n "$is_space" ]; then
                echo continue $i $is_space
                continue
            fi
            is_space="true"
            args+=("$s")
            s=""
            continue
        fi

        is_space=""
        s+="$c"
    done

    if [ "$last_quote" != "$notquote" ]; then
        >&2 echo "error: quote not terminated"
        return 1
    fi

    for arg in "${args[@]}"; do
        echo "$arg"
    done
    return 0
}

1nce_login() {
    USERNAME="$1"
    PASSWORD="$2"
    BASIC_AUTH="$(echo -n "${USERNAME}:${PASSWORD}" | base64)"
    echo $(
        curl -s --request POST \
            --url https://api.1nce.com/management-api/oauth/token \
            --header 'accept: application/json' \
            --header "authorization: Basic $BASIC_AUTH" \
            --header 'content-type: application/json' \
            --data '
            {
                "grant_type": "client_credentials"
            }
            ' |
            jq -r '.access_token'
    )
}

sim_by_imei() {
    IMEI="$1"
    ACCESS_TOKEN="$2"
    echo $(
        curl -s --request GET \
            --url "https://api.1nce.com/management-api/v1/sims?page=1&pageSize=100&q=imei:$IMEI" \
            --header 'accept: application/json' \
            --header "authorization: Bearer ${ACCESS_TOKEN}" |
            jq -r '.[].iccid'
    )
}

sim_list() {
    ACCESS_TOKEN="$1"
    SIM_LIST=""
    PAGE=1
    while true; do
        SIM_LIST_NEW=$(
            curl -s --request GET \
                --url "https://api.1nce.com/management-api/v1/sims?page=${PAGE}&pageSize=100" \
                --header 'accept: application/json' \
                --header "authorization: Bearer ${ACCESS_TOKEN}" |
                jq -r '.[].iccid'
        )
        if [ -z "$SIM_LIST_NEW" ]; then
            break
        fi
        SIM_LIST="${SIM_LIST} ${SIM_LIST_NEW}"
        PAGE=$((PAGE + 1))
    done
    echo "${SIM_LIST}" | xargs
}

sim_events() {
    SIM="$1"
    ACCESS_TOKEN="$2"
    PAGE=1
    MAX_PAGE=2
    while true; do
        if [ "$PAGE" -gt "$MAX_PAGE" ]; then
            break
        fi
        SIM_EVENTS=$(
            curl -s --request GET \
                --url "https://api.1nce.com/management-api/v1/sims/${SIM}/events?page=${PAGE}&pageSize=100&sort=-timestamp" \
                --header 'accept: application/json' \
                --header "authorization: Bearer ${ACCESS_TOKEN}"
        )
        MAX_PAGE=$(jq '.totalPages' <<<"$SIM_EVENTS")
        SIM_EVENTS=$(
            echo -n $SIM_EVENTS |
                jq '.events[] | .timestamp + "|" + .iccid + "|" + .imei + "|" + .event_type + "|" + .operator'
        )
        if [ -n "$SIM_EVENTS" ]; then
            # Create array from multi-line string
            IFS=$'\r\n' GLOBIGNORE='*' args=($(parseargs "$SIM_EVENTS"))

            # Show each of the arguments array
            for line in "${args[@]}"; do
                #if [[ $line =~ ^.+PDP.+$ ]]; then
                echo "$line"
                #fi
            done
        fi
        PAGE=$((PAGE + 1))
    done
}

single_sim_events() {
    IMEI="$1"
    ACCESS_TOKEN="$2"
    SIM_LIST=$(sim_by_imei "${IMEI}" "${ACCESS_TOKEN}")

    for SIM in ${SIM_LIST}; do
        if (("null" != "${SIM}")); then
            sim_events "$SIM" "$ACCESS_TOKEN"
        fi
    done
}

all_sim_events() {
    ACCESS_TOKEN="$1"
    SIM_LIST=$(sim_list "${ACCESS_TOKEN}")
    echo ${SIM_LIST}

    for SIM in ${SIM_LIST}; do
        if (("null" != "${SIM}")); then
            sim_events "$SIM" "$ACCESS_TOKEN"
        fi
    done
}

USERNAME="$1"
PASSWORD="$2"
ACCESS_TOKEN=$(1nce_login "${USERNAME}" "${PASSWORD}")
if [ "$#" -eq 3 ]; then
    # Unmask the IMEI
    SIM="${3%?}"
    echo "Events for SIM with IMEI ${SIM}"
    single_sim_events "${SIM}" "${ACCESS_TOKEN}"
else
    all_sim_events "${ACCESS_TOKEN}"
fi
