defmodule ExLibnice.App do
  @moduledoc false
  use Application

  @impl true
  def start(_start_type, _start_args) do
    children =
      if Application.get_env(:ex_libnice, :mdns, true) do
        [ExLibnice.Mdns]
      else
        []
      end

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
