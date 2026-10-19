### `mdg_control_pb`

```proto
message allocate_pairing_channel {   // mdg.control.allocate_pairing_channel
  required uint32 req_id = 1;
}
```

```proto
message allocate_pairing_channel_reply {   // mdg.control.allocate_pairing_channel_reply
  required uint32 req_id = 1;
  required enum result = 2;
  optional string pair_id = 3;
  optional uint64 end_of_validity = 4;
}
```

```proto
message bye {   // mdg.control.bye
  required enum reason = 1;
  optional string reason_text = 2;
}
```

```proto
message endpoint {   // mdg.control.endpoint
  required bytes host = 1;
  required uint32 port = 2;
}
```

```proto
message handshake {   // mdg.control.handshake
  required fixed32 magic = 1;
  required uint32 version_major = 2;
  required uint32 version_minor = 3;
  repeated message property = 4;
}
```

```proto
message incoming_call {   // mdg.control.incoming_call
  required uint32 req_id = 1;
  required message routing = 2;
  optional string protocol = 3;
  optional string ticket = 4;
}
```

```proto
message incoming_call_reply {   // mdg.control.incoming_call_reply
  required uint32 req_id = 1;
  required bool will_accept_call = 2;
}
```

```proto
message incoming_pairing_call {   // mdg.control.incoming_pairing_call
  required uint32 req_id = 1;
  required message routing = 2;
  required string pair_id = 3;
}
```

```proto
message incoming_pairing_call_reply {   // mdg.control.incoming_pairing_call_reply
  required uint32 req_id = 1;
  required bool will_accept_call = 2;
}
```

```proto
message ping {   // mdg.control.ping
  required uint32 req_id = 1;
  optional uint32 perceived_qos = 2;
}
```

```proto
message ping_reply {   // mdg.control.ping_reply
  required uint32 req_id = 1;
}
```

```proto
message place_call {   // mdg.control.place_call
  required uint32 req_id = 1;
  required string peer_name = 2;
  optional string protocol = 3;
  optional string ticket = 4;
}
```

```proto
message place_call_reply {   // mdg.control.place_call_reply
  required uint32 req_id = 1;
  required enum result = 2;
  optional message routing = 3;
  optional string result_text = 4;
}
```

```proto
message place_pairing_call {   // mdg.control.place_pairing_call
  required uint32 req_id = 1;
  required string pair_id = 2;
}
```

```proto
message place_pairing_call_reply {   // mdg.control.place_pairing_call_reply
  required uint32 req_id = 1;
  required enum result = 2;
  optional message routing = 3;
  optional string result_text = 4;
}
```

```proto
message property {   // mdg.control.property
  required string key = 1;
  required string value = 2;
}
```

```proto
message reconnect {   // mdg.control.reconnect
  optional message new_host = 1;
  optional uint32 suggested_delay = 2;
}
```

```proto
message routing_info {   // mdg.control.routing_info
  required string peer_name = 3;
  repeated message router = 4;
  required bytes token = 5;
}
```

```proto
message set_peer_whitelist {   // mdg.control.set_peer_whitelist
  required uint32 req_id = 1;
  repeated string peer_name = 2;
}
```

```proto
message set_peer_whitelist_reply {   // mdg.control.set_peer_whitelist_reply
  required uint32 req_id = 1;
}
```

Enums / tags without listed fields: `allocate_pairing_channel_result`, `bye_reason`, `control_message_tag`, `place_call_result`

### `mdg_routing_pb`

```proto
message GoAhead {   // mdg.routing.GoAhead
  optional string selected_protocol = 1;
}
```

```proto
message Handshake {   // mdg.routing.Handshake
  required fixed32 magic = 1;
  required uint32 version_major = 2;
  required uint32 version_minor = 3;
  required bytes token = 4;
  repeated string supported_protocols = 5;
}
```

```proto
message RoutingError {   // mdg.routing.RoutingError
  required enum error = 1;
}
```

Enums / tags without listed fields: `PleaseHold`, `RoutingErrorTypes`, `routing_message_tag`

### `mdg_pairing_pb`

```proto
message contact_info {   // contact_info
  optional string name = 1;
}
```

```proto
message pace_client_hello {   // pace_client_hello
  required fixed32 magic = 1;
  required uint32 version_major = 2;
  required uint32 version_minor = 3;
}
```

```proto
message pace_pk {   // pace_pk
  required bytes pk = 1;
}
```

```proto
message pace_proof {   // pace_proof
  required bytes token = 1;
}
```

```proto
message pace_server_hello {   // pace_server_hello
  required uint32 version_major = 1;
  required uint32 version_minor = 2;
  required bytes salt = 3;
  required bytes iv = 4;
  required bytes z = 5;
}
```

```proto
message pace_xy {   // pace_xy
  required bytes xy = 1;
}
```

Enums / tags without listed fields: `pairing_message_tag`

### `mdg_library_pb`

```proto
message NegResponse {   // mdg.library.NegResponse
  required uint32 request_id = 1;
  required string error_text = 2;
}
```

```proto
message Notification {   // mdg.library.Notification
  required string event = 1;
  repeated message parameters = 2;
}
```

```proto
message PosResponse {   // mdg.library.PosResponse
  required uint32 request_id = 1;
  required string response = 2;
}
```

```proto
message Property {   // mdg.library.Property
  required string key = 1;
  required string value = 2;
}
```

```proto
message Request {   // mdg.library.Request
  required uint32 request_id = 1;
  required string operation = 2;
  repeated message parameters = 3;
}
```

Enums / tags without listed fields: `control_message_tag`
