input {
    syslog {
        port => 514
    }
}

filter {
    # Add filters here if needed
}

output {
    elasticsearch {
        hosts => ["http://localhost:9200"]
        index => "kernel-logs-%{+YYYY.MM.dd}"
    }
}
