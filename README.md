# ExLibnice

[![Hex.pm](https://img.shields.io/hexpm/v/ex_libnice.svg)](https://hex.pm/packages/ex_libnice)
[![API Docs](https://img.shields.io/badge/api-docs-yellow.svg?style=flat)](https://hexdocs.pm/ex_libnice/)
[![CircleCI](https://circleci.com/gh/membraneframework/ex_libnice.svg?style=svg)](https://circleci.com/gh/membraneframework/ex_libnice)

Libnice-based Interactive Connectivity Establishment (ICE) protocol support for Elixir.

It is a part of [Membrane Multimedia Framework](https://membraneframework.org).

## Installation

The package can be installed by adding `ex_libnice` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
	{:ex_libnice, "~> 0.8.0"}
  ]
end
```

## Usage

Basically this library works similarly to [libnice].

`ExLibnice` can work both as CNode and as NIF.
By default `CNode` implementation is used however, user can change it by passing proper option while starting `ExLibnice` (see below) or by `config.exs`:

```elixir
config :ex_libnice, impl: :NIF
```

User can also choose whether to resolve mDNS addresses or not:

```elixir
config :ex_libnice, mdns: false
```

Example flow can look in the following way (this is not complete i.e. runnable example).

Listed functions must be invoked on both peers.
```elixir
# Init ExLibnice
{:ok, pid} =
  ExLibnice.start_link(
    impl: NIF,
    parent: self(),
    stun_servers: [
      %{server_addr: {64, 233, 161, 127}, server_port: 19_302},
      %{server_addr: "stun1.l.google.com", server_port: 19_302}
    ],
    controlling_mode: true,
    port_range: 0..0
  )

# Add stream, get local credentials
{:ok, stream_id} = ExLibnice.add_stream(ice, 1, "audio")
{:ok, credentials} = ExLibnice.get_local_credentials(ice, stream_id)

# Send local credentials to the remote peer
:socket.send(peer_socket, credentials)
```

```elixir
# Receive remote credentials and set them on ExLibnice
{:ok, credentials} = :socket.recv(peer_socket)
:ok = ExLibnice.set_remote_credentials(ice, peer_credentials, stream_id)

# Start gathering candidates
:ok = ExLibnice.gather_candidates(ice, stream_id)
```

```elixir
# Now we should prepare for receiving messages in form of `{:new_candidate_full, candidate}`
# and send them to the remote peer. If module that runs ExLibnice is a GenServer we can use
# handle_info/2 callback
@impl true
def handle_info({:new_candidate_full, candidate}, {peer_socket: peer_socket} = state) do
  :socket.send(peer_socket, {:peer_new_candidate_full, candidate})
end
```

```elixir
# Set received peer candidates.
:ok = ExLibnice.set_remote_candidate(ice, peer_candidate, stream_id, 1)
```

This will start connectivity checks. Receiving message
`{:component_state_ready, stream_id, component_id}` indicates that the given component in the given
stream is ready to send and receive messages.


For more complete examples please refer to
[membrane_ice_plugin](https://github.com/membraneframework/membrane_ice_plugin) where we use
`ex_libnice` or our integration test.


## Copyright and License

Copyright 2020, [Software Mansion](https://swmansion.com/?utm_source=git&utm_medium=readme&utm_campaign=membrane_ice)

[![Software Mansion](https://logo.swmansion.com/logo?color=white&variant=desktop&width=200&tag=membrane-github)](https://swmansion.com/?utm_source=git&utm_medium=readme&utm_campaign=membrane_ice)

Licensed under the [Apache License, Version 2.0](LICENSE)

[libnice]: https://libnice.freedesktop.org/

