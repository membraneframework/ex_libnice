defmodule ExLibnice do
  @moduledoc """
  Module that wraps functions from [libnice](https://libnice.freedesktop.org/libnice/index.html).

  For more information about each function please refer to [libnice] documentation.
  """

  use GenServer

  require Logger
  require Unifex.CNode

  defmodule State do
    @moduledoc false

    @type t :: %__MODULE__{
            parent: pid,
            cnode: Unifex.CNode.t(),
            stream_components: %{stream_id: integer(), n_components: integer()}
          }
    defstruct parent: nil,
              cnode: nil,
              stream_components: %{}
  end

  @typedoc """
  Fully qualified domain name e.g. "my.domain.com".
  """
  @type fqdn() :: String.t()

  @type stun_server() :: %{server_addr: :inet.ip_address() | fqdn(), server_port: 0..65535}

  @typedoc """
  Type describing TURN server configuration
  """
  @type relay_info :: %{
          server_addr: :inet.ip_address() | fqdn(),
          server_port: 0..65535,
          username: String.t(),
          password: String.t(),
          relay_type: :udp | :tcp | :tls
        }

  @typedoc """
  Type describing ExLibnice configuration.

  It's a keyword list containing the following keys:
  * parent - pid of calling process
  * stun_servers - list of stun servers in form of ip:port
  * controlling_mode - refer to RFC 8445 section 4 - Controlling and Controlled Agent
  * min_port..max_port - the port range to use. Pass 0..0 if you not willing to set it.

  Passed port range will be set for each newly added stream. At this moment it is not possible to
  set port range per stream.
  """
  @type opts_t :: [
          parent: pid(),
          stun_servers: [stun_server()],
          controlling_mode: boolean(),
          port_range: 0..65_535
        ]

  @doc """
  Spawns new process responsible for interacting with `libnice`.
  """
  @spec start_link(opts :: opts_t) :: {:ok, pid()}
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Adds a new stream with `n_components` components. `name` is optional but not passing it will
  influence on SDP string format, see `generate_local_sdp/1`.
  """
  @spec add_stream(pid :: pid(), n_components :: integer(), name :: String.t()) ::
          {:ok, integer()}
          | {:error,
             :failed_to_add_stream | :invalid_stream_or_duplicate_name | :failed_to_attach_recv}
  def add_stream(pid, n_components, name \\ "") do
    GenServer.call(pid, {:add_stream, n_components, name})
  end

  @doc """
  Removes stream with id `stream_id`.
  """
  @spec remove_stream(pid :: pid(), stream_id :: integer()) :: :ok
  def remove_stream(pid, stream_id) do
    GenServer.cast(pid, {:remove_stream, stream_id})
  end

  @doc """
  Sets TURN server. Can be called multiple times for the same component to add many TURN
  servers.
  """
  @spec set_relay_info(
          pid :: pid(),
          stream_id :: integer(),
          component_id :: integer() | [integer()] | :all,
          relay_info :: relay_info() | [relay_info()]
        ) ::
          :ok
          | {:error,
             :bad_stream_id | :bad_relay_type | :failed_to_resolve_addr | :failed_to_set_turn}
  def set_relay_info(pid, stream_id, component_id, relay_info) do
    GenServer.call(pid, {:set_relay_info, stream_id, component_id, relay_info})
  end

  @doc """
  Forget all TURN servers for given component.
  """
  @spec forget_relays(pid :: pid(), stream_id :: integer(), component_id :: integer()) ::
          :ok | {:error, :component_not_found}
  def forget_relays(pid, stream_id, component_id) do
    GenServer.call(pid, {:forget_relays, stream_id, component_id})
  end

  @doc """
  Generates a SDP string containing the local candidates and credentials for all streams and
  components.

  Notice that:
  - local candidates will be present in the result SDP only if `gather_candidates/1` has been
  invoked previously
  - if a stream is created without a name the 'm' line will contain '-' mark but SDP in this form
  will not be parsable by `parse_remote_sdp/2`
  """
  @spec generate_local_sdp(pid :: pid()) :: {:ok, sdp :: String.t()}
  def generate_local_sdp(pid) do
    GenServer.call(pid, :generate_local_sdp)
  end

  @doc """
  Parses a remote SDP string setting credentials and remote candidates for proper streams and
  components. It is important that `m` line does not contain `-` mark but the name of the stream.
  """
  @spec parse_remote_sdp(pid :: pid(), sdp :: String.t()) ::
          {:ok, added_cand_num :: integer()} | {:error, :failed_to_parse_sdp}
  def parse_remote_sdp(pid, sdp) do
    GenServer.call(pid, {:parse_remote_sdp, sdp})
  end

  @doc """
  Returns local credentials for stream with id `stream_id`.
  """
  @spec get_local_credentials(pid :: pid(), stream_id :: integer()) ::
          {:ok, credentials :: String.t()} | {:error, :failed_to_get_credentials}
  def get_local_credentials(pid, stream_id) do
    GenServer.call(pid, {:get_local_credentials, stream_id})
  end

  @doc """
  Sets remote credentials for stream with `stream_id`.
  Credentials have to be passed in form of `ufrag pwd`.
  """
  @spec set_remote_credentials(pid :: pid(), credentials :: String.t(), stream_id :: integer()) ::
          :ok | {:error, :failed_to_set_credentials}
  def set_remote_credentials(pid, credentials, stream_id) do
    GenServer.call(pid, {:set_remote_credentials, credentials, stream_id})
  end

  @doc """
  Starts gathering candidates process for stream with id `stream_id`.

  May cause the parent process receive following messages:
  - `{:new_candidate_full, candidate}` - new local candidate
  - `{:candidate_gathering_done, stream_id}` - gathering candidates for stream with `stream_id`
  has been done
  """
  @spec gather_candidates(pid :: pid(), stream_id :: integer()) ::
          :ok | {:error, :invalid_stream_or_allocation}
  def gather_candidates(pid, stream_id) do
    GenServer.call(pid, {:gather_candidates, stream_id})
  end

  @doc """
  Indicates that all remote candidates for stream with id `stream_id` have been passed.

  After receiving this message components can change their state to `FAILED` if all their
  connectivity checks have failed. Not sending this message will cause components stay in
  `CONNECTING` state. (In fact there is a bug and components can change their state to `FAILED`
  even without sending this message. Please refer to
  [#120](https://gitlab.freedesktop.org/libnice/libnice/-/issues/120.)
  """
  @spec peer_candidate_gathering_done(pid :: pid(), stream_id :: integer()) ::
          :ok | {:error, :stream_not_found}
  def peer_candidate_gathering_done(pid, stream_id) do
    GenServer.call(pid, {:peer_candidate_gathering_done, stream_id})
  end

  @doc """
  Sets remote candidate for component with id `component_id` in stream with id `stream_id`.
  Candidate has to be passed as SDP string.

  May cause the parent process receive following messages:
  - `{:new_remote_candidate_full, candidate}` - new remote (prflx) candidate
  - `{:new_selected_pair, stream_id, component_id, lfoundation, rfoundation}` - new selected pair
  - `{:component_state_failed, stream_id, component_id}` - component with id `component_id` in
  stream with id `stream_id` has changed state to FAILED
  - `{:component_state_ready, stream_id, component_id}` - component with id `component_id` in stream
  with id `stream_id` has changed state to READY i.e. it is ready to receive and send data
  """
  @spec set_remote_candidate(
          pid :: pid(),
          candidate :: String.t(),
          stream_id :: integer(),
          component_id :: integer()
        ) :: :ok | {:error, :failed_to_parse_sdp_string | :failed_to_set}
  def set_remote_candidate(pid, candidate, stream_id, component_id) do
    GenServer.call(pid, {:set_remote_candidate, candidate, stream_id, component_id})
  end

  @doc """
  Restarts all streams.
  """
  @spec restart(pid :: pid()) :: :ok | {:error, :failed_to_restart}
  def restart(pid) do
    GenServer.call(pid, :restart)
  end

  @doc """
  Restarts stream with id `stream_id`.
  """
  @spec restart_stream(pid :: pid(), stream_id :: integer()) :: :ok | {:error, :failed_to_restart}
  def restart_stream(pid, stream_id) do
    GenServer.call(pid, {:restart_stream, stream_id})
  end

  @doc """
  Sends payload on component with id `component_id` in stream with id `stream_id`. Payload has to
  be in a binary format.
  """
  @spec send_payload(
          pid :: pid(),
          stream_id :: integer(),
          component_id :: integer(),
          payload :: binary()
        ) :: :ok | {:error, :failed_to_send}
  def send_payload(pid, stream_id, component_id, payload) do
    GenServer.call(pid, {:send_payload, stream_id, component_id, payload})
  end

  # Server API
  @impl true
  def init(opts) do
    min_port..max_port = opts[:port_range]

    {:ok, cnode} = Unifex.CNode.start_link(:native)

    {:ok, stun_servers} = lookup_stun_servers(opts[:stun_servers])

    :ok =
      Unifex.CNode.call(cnode, :init, [
        stun_servers,
        opts[:controlling_mode],
        min_port,
        max_port
      ])

    state = %State{parent: opts[:parent], cnode: cnode}

    {:ok, state}
  end

  @impl true
  def handle_call({:add_stream, n_components}, from, state) do
    handle_call({:add_stream, n_components, ""}, from, state)
  end

  @impl true
  def handle_call({:add_stream, n_components, name}, _from, %{cnode: cnode} = state) do
    case Unifex.CNode.call(cnode, :add_stream, [n_components, name]) do
      {:ok, stream_id} ->
        Logger.debug("New stream_id: #{stream_id}")
        {:reply, {:ok, stream_id}, put_in(state.stream_components[stream_id], n_components)}

      {:error, cause} ->
        Logger.warn("""
        Couldn't add stream with #{n_components} components and name "#{inspect(name)}": \
        #{inspect(cause)}
        """)

        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call({:set_relay_info, stream_id, component_id, relay_info}, _from, state) do
    ret =
      Bunch.listify(relay_info)
      |> Bunch.Enum.try_each(&do_set_relay_info(state, stream_id, component_id, &1))

    {:reply, ret, state}
  end

  @impl true
  def handle_call({:forget_relays, stream_id, component_id}, _from, %{cnode: cnode} = state) do
    case Unifex.CNode.call(cnode, :forget_relays, [stream_id, component_id]) do
      :ok ->
        {:reply, :ok, state}

      {:error, cause} ->
        Logger.warn("""
        Couldn't forget TURN servers for component: #{inspect(component_id)} in stream: \
        #{inspect(stream_id)}, reason: #{inspect(cause)}
        """)

        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call(:generate_local_sdp, _from, %{cnode: cnode} = state) do
    {:ok, local_sdp} = Unifex.CNode.call(cnode, :generate_local_sdp)
    Logger.debug("local sdp: #{inspect(local_sdp)}")
    {:reply, {:ok, local_sdp}, state}
  end

  @impl true
  def handle_call({:parse_remote_sdp, remote_sdp}, _from, %{cnode: cnode} = state) do
    case Unifex.CNode.call(cnode, :parse_remote_sdp, [remote_sdp]) do
      {:ok, added_cand_num} ->
        Logger.debug("parse_remote_sdp: ok; added #{added_cand_num} candidates")
        {:reply, {:ok, added_cand_num}, state}

      {:error, cause} ->
        Logger.warn("Couldn't parse remote sdp #{inspect(remote_sdp)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call({:get_local_credentials, stream_id}, _from, %{cnode: cnode} = state) do
    case Unifex.CNode.call(cnode, :get_local_credentials, [stream_id]) do
      {:ok, credentials} ->
        Logger.debug("local credentials: #{credentials}")
        {:reply, {:ok, credentials}, state}

      {:error, cause} ->
        Logger.error("get_local_credentials: #{inspect(cause)}")
        {{:error, cause}, state}
    end
  end

  @impl true
  def handle_call(
        {:set_remote_credentials, credentials, stream_id},
        _from,
        %{cnode: cnode} = state
      ) do
    case Unifex.CNode.call(cnode, :set_remote_credentials, [credentials, stream_id]) do
      :ok ->
        Logger.debug("set_remote_credentials: ok")
        {:reply, :ok, state}

      {:error, cause} ->
        Logger.error("set_remote_credentials: #{inspect(cause)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call({:gather_candidates, stream_id} = msg, _from, %{cnode: cnode} = state) do
    case Unifex.CNode.call(cnode, :gather_candidates, [stream_id]) do
      :ok ->
        Logger.debug("#{inspect(msg)}")
        {:reply, :ok, state}

      {:error, cause} ->
        Logger.error("gather_candidates: #{inspect(msg)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call(
        {:peer_candidate_gathering_done, stream_id},
        _ctx,
        %{cnode: cnode} = state
      ) do
    case Unifex.CNode.call(cnode, :peer_candidate_gathering_done, [stream_id]) do
      :ok ->
        Logger.debug("peer_candidate_gathering_done: ok")
        {:reply, :ok, state}

      {:error, cause} ->
        Logger.warn("peer_candidate_gathering_done: #{inspect(cause)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call(
        {:set_remote_candidate, candidate, stream_id, component_id},
        _from,
        %{cnode: cnode} = state
      ) do
    case Unifex.CNode.call(cnode, :set_remote_candidate, [candidate, stream_id, component_id]) do
      :ok ->
        Logger.debug("Set remote candidate: #{inspect(candidate)}")
        {:reply, :ok, state}

      {:error, cause} ->
        Logger.warn("Couldn't set remote candidate: #{inspect(cause)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call(:restart, _from, %{cnode: cnode} = state) do
    case Unifex.CNode.call(cnode, :restart) do
      :ok ->
        Logger.debug("ICE restarted")
        {:reply, :ok, state}

      {:error, cause} ->
        Logger.warn("Couldn't restart ICE")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call({:restart_stream, stream_id}, _from, %{cnode: cnode} = state) do
    case Unifex.CNode.call(cnode, :restart_stream, [stream_id]) do
      :ok ->
        Logger.debug("Stream #{inspect(stream_id)} restarted")
        {:reply, :ok, state}

      {:error, cause} ->
        Logger.warn("Couldn't restart stream #{inspect(stream_id)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call(
        {:send_payload, stream_id, component_id, payload},
        _from,
        %{cnode: cnode} = state
      ) do
    case Unifex.CNode.call(cnode, :send_payload, [stream_id, component_id, payload]) do
      :ok ->
        {:reply, :ok, state}

      {:error, cause} ->
        Logger.warn("Couldn't send payload: #{inspect(cause)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_cast({:remove_stream, stream_id}, %{cnode: cnode} = state) do
    :ok = Unifex.CNode.call(cnode, :remove_stream, [stream_id])
    Logger.debug("remove_stream #{stream_id}: ok")
    {_n_components, state} = pop_in(state.stream_components[stream_id])
    {:noreply, state}
  end

  @impl true
  def handle_info({:new_candidate_full, _cand} = msg, %State{parent: parent} = state) do
    Logger.debug("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info({:new_remote_candidate_full, _cand} = msg, %State{parent: parent} = state) do
    Logger.debug("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info({:candidate_gathering_done, _stream_id} = msg, %State{parent: parent} = state) do
    Logger.debug("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:new_selected_pair, _stream_id, _component_id, _lfoundation, _rfoundation} = msg,
        %State{parent: parent} = state
      ) do
    Logger.debug("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:component_state_ready, _stream_id, _component_id} = msg,
        %State{parent: parent} = state
      ) do
    Logger.debug("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:component_state_failed, _stream_id, _component_id} = msg,
        %State{parent: parent} = state
      ) do
    Logger.warn("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:ice_payload, _stream_id, _component_id, _payload} = msg,
        %State{parent: parent} = state
      ) do
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warn("Unknown message #{inspect(msg)}")
    {:noreply, state}
  end

  defp lookup_stun_servers(stun_servers) do
    Bunch.Enum.try_map(stun_servers, fn %{server_addr: addr, server_port: port} ->
      case lookup_addr(addr) do
        {:ok, ip} -> {:ok, "#{:inet.ntoa(ip)}:#{port}"}
        {:error, _cause} = error -> error
      end
    end)
  end

  defp do_set_relay_info(state, stream_id, components, relay_info) when is_list(components),
    do: Bunch.Enum.try_each(components, &do_set_relay_info(state, stream_id, &1, relay_info))

  defp do_set_relay_info(state, stream_id, :all, relay_info) do
    case Map.get(state.stream_components, stream_id) do
      nil ->
        Logger.warn("Couldn't set TURN servers. No stream with id #{inspect(stream_id)}")

        {:error, :bad_stream_id}

      n_components ->
        Bunch.Enum.try_each(1..n_components, &do_set_relay_info(state, stream_id, &1, relay_info))
    end
  end

  defp do_set_relay_info(
         _state,
         stream_id,
         component_id,
         %{server_addr: server_addr, server_port: server_port, relay_type: relay_type}
       )
       when relay_type not in [:udp, :tcp, :tls] do
    Logger.warn("""
    Couldn't set TURN server #{inspect(server_addr)} #{inspect(server_port)} \
    #{inspect(relay_type)} for component: #{inspect(component_id)} in stream: \
    #{inspect(stream_id)}, cause: bad_relay_type
    """)

    {:error, :bad_relay_type}
  end

  defp do_set_relay_info(%{cnode: cnode}, stream_id, component_id, %{
         server_addr: server_addr,
         server_port: server_port,
         username: username,
         password: password,
         relay_type: relay_type
       }) do
    case lookup_addr(server_addr) do
      {:error, cause} = error ->
        Logger.warn("""
        Couldn't set TURN server #{inspect(server_addr)} #{inspect(server_port)} \
        #{inspect(relay_type)} for component: #{inspect(component_id)} in stream: \
        #{inspect(stream_id)}, cause: #{inspect(cause)}
        """)

        error

      {:ok, server_ip} ->
        case Unifex.CNode.call(cnode, :set_relay_info, [
               stream_id,
               component_id,
               :inet.ntoa(server_ip) |> to_string(),
               server_port,
               username,
               password,
               Atom.to_string(relay_type)
             ]) do
          :ok ->
            :ok

          {:error, cause} = error ->
            Logger.warn("""
            Couldn't set TURN server #{inspect(server_addr)} #{inspect(server_port)} \
            #{inspect(relay_type)} for component: #{inspect(component_id)} in stream: \
            #{inspect(stream_id)}, cause: #{inspect(cause)}
            """)

            error
        end
    end
  end

  defp lookup_addr({_a, _b, _c, _d} = addr), do: {:ok, addr}
  defp lookup_addr({_a, _b, _c, _d, _e, _f, _g, _h} = addr), do: {:ok, addr}

  defp lookup_addr(addr) do
    case :inet_res.lookup(addr, :in, :a) do
      [] -> {:error, :failed_to_lookup_address}
      [h | _t] -> {:ok, h}
    end
  end
end
