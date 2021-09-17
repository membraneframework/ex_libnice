# credo:disable-for-this-file Credo.Check.Readability.Specs
defmodule ExLibnice.Support.TestPeer do
  @moduledoc false

  use GenServer

  require Logger

  @payload <<1, 1, 2, 3, 5, 8, 13, 21, 34>>

  defmodule State do
    @moduledoc false

    defstruct parent: nil,
              impl: nil,
              peer: nil,
              ice: nil,
              stream_id: nil
  end

  # Client API
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  def set_peer(pid, peer) do
    GenServer.cast(pid, {:set_peer, peer})
  end

  def start(pid, controlling_mode) do
    GenServer.cast(pid, {:start, controlling_mode})
  end

  def send(pid) do
    GenServer.call(pid, :send)
  end

  # Server API
  @impl true
  def init(opts) do
    {:ok, %State{parent: opts[:parent], impl: opts[:impl]}}
  end

  @impl true
  def handle_cast({:set_peer, peer}, state) do
    {:noreply, %State{state | peer: peer}}
  end

  @impl true
  def handle_cast({:start, controlling_mode}, %{peer: peer, impl: impl} = state) do
    {:ok, ice} =
      ExLibnice.start_link(
        impl: impl,
        parent: self(),
        stun_servers: [%{server_addr: {64, 233, 161, 127}, server_port: 19_302}],
        controlling_mode: controlling_mode,
        port_range: 0..0
      )

    {:ok, stream_id} = ExLibnice.add_stream(ice, 1)
    {:ok, credentials} = ExLibnice.get_local_credentials(ice, stream_id)

    send(peer, {:peer_credentials, credentials})

    :ok = ExLibnice.gather_candidates(ice, stream_id)

    {:noreply, %State{state | ice: ice, stream_id: stream_id}}
  end

  @impl true
  def handle_call(:send, _from, %{ice: ice, stream_id: stream_id} = state) do
    :ok = ExLibnice.send_payload(ice, stream_id, 1, @payload)
    {:reply, :ok, state}
  end

  @impl true
  def handle_info({:peer_credentials, credentials}, %{ice: ice, stream_id: stream_id} = state) do
    :ok = ExLibnice.set_remote_credentials(ice, credentials, stream_id)
    {:noreply, state}
  end

  @impl true
  def handle_info({:new_candidate_full, candidate}, %{peer: peer} = state) do
    send(peer, {:peer_new_candidate_full, candidate})
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:peer_new_candidate_full, candidate},
        %{ice: ice, stream_id: stream_id} = state
      ) do
    ExLibnice.set_remote_candidate(ice, candidate, stream_id, 1)
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:component_state_ready, _stream_id, _component_id, _port},
        %{parent: parent} = state
      ) do
    send(parent, {self(), :ready})
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:ice_payload, _stream_id, _component_id, payload},
        %State{parent: parent} = state
      ) do
    if payload == @payload do
      send(parent, {self(), :received})
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(other, state) do
    Logger.debug("Other msg: #{inspect(other)}")
    {:noreply, state}
  end
end
