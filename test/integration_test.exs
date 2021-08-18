defmodule ExLibnice.IntegrationTest do
  use ExUnit.Case, async: true

  describe "ice-trickle" do
    test "NIF wrapper" do
      test_ice_trickle(NIF)
    end

    test "CNode wrapper" do
      test_ice_trickle(CNode)
    end
  end

  defp test_ice_trickle(impl) do
    {:ok, tx_pid} = ExLibnice.Support.TestPeer.start_link(parent: self(), impl: impl)
    {:ok, rx_pid} = ExLibnice.Support.TestPeer.start_link(parent: self(), impl: impl)

    :ok = ExLibnice.Support.TestPeer.set_peer(tx_pid, rx_pid)
    :ok = ExLibnice.Support.TestPeer.set_peer(rx_pid, tx_pid)

    :ok = ExLibnice.Support.TestPeer.start(tx_pid, true)
    :ok = ExLibnice.Support.TestPeer.start(rx_pid, false)

    assert_receive({^tx_pid, :ready}, 2000)
    assert_receive({^rx_pid, :ready}, 2000)

    :ok = ExLibnice.Support.TestPeer.send(tx_pid)

    assert_receive {^rx_pid, :received}
  end
end
