#!/bin/bash
log_file=$1 # eg "/var/log/waagent.log"
output_prefix=$2 # eg "waagent_log"

max_size=$((1024 * 1024)) # 1 MB in bytes

# Get today's date in the same format as the log timestamp (assuming YYYY-MM-DD)
today=$(date +"%Y-%m-%d")

file_index=1
current_file="${output_prefix}_${file_index}.json"
echo "[" > "$current_file"
first_line=true

current_size=$(stat -c%s "$current_file")

while IFS= read -r line; do
    timestamp=$(echo "$line" | awk '{print $1}')

    # Skip lines that don't match today's date
    if [[ "$timestamp" != "$today"* ]]; then
        continue
    fi

    # replace quote with \"
    # replace backslashed quote with \\ and \"
    raw_data=$(echo "$line" | sed 's/\"/\\\"/g; s/\\\\\"/\\\\\\\"/g')

    json_line="  {\"TimeGenerated\": \"$timestamp\", \"RawData\": \"$raw_data\"}"

    # Add comma if not first line
    if [ "$first_line" = true ]; then
        first_line=false
    else
        json_line=",$json_line"
    fi

    # Check if adding this line exceeds max size
    if (( current_size + ${#json_line} > max_size )); then
        echo "]" >> "$current_file"
        file_index=$((file_index + 1))
        current_file="${output_prefix}_${file_index}.json"
        echo "[" > "$current_file"
        first_line=true
        current_size=$(stat -c%s "$current_file")
    fi

    echo "$json_line" >> "$current_file"
    current_size=$(stat -c%s "$current_file")
done < "$log_file"

echo "]" >> "$current_file"
