defmodule ExLibnice do
  @moduledoc """
  Module that wraps functions from [libnice](https://libnice.freedesktop.org/libnice/index.html).
  """

  use GenServer

  require Logger
  require Unifex.CNode

  defmodule State do
    @moduledoc false

    @type t :: %__MODULE__{
            parent: pid,
            cnode: Unifex.CNode.t()
          }
    defstruct parent: nil,
              cnode: nil
  end

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
          stun_servers: [String.t()],
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
    # TODO support TURN servers
    turn_servers = []
    min_port..max_port = opts[:port_range]

    {:ok, cnode} = Unifex.CNode.start_link(:native)

    :ok =
      Unifex.CNode.call(cnode, :init, [
        opts[:stun_servers],
        turn_servers,
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
        {:reply, {:ok, stream_id}, state}

      {:error, cause} ->
        Logger.warn("""
        Couldn't add stream with #{n_components} components and name "#{inspect(name)}":
        #{inspect(cause)}
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
end
