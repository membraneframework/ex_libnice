defmodule ExLibnice.BundlexProject do
  use Bundlex.Project

  def project do
    [
      natives: natives()
    ]
  end

  defp get_libnice_url() do
    case Bundlex.get_target() do
      %{os: "linux"} ->
        {:precompiled,
         "https://github.com/membraneframework-precompiled/precompiled_libnice/releases/latest/download/libnice_linux.tar.gz"}

      %{architecture: "x86_64", os: "darwin" <> _rest_of_os_name} ->
        {:precompiled,
         "https://github.com/membraneframework-precompiled/precompiled_libnice/releases/latest/download/libnice_macos_intel.tar.gz"}

      %{architecture: "aarch64", os: "darwin" <> _rest_of_os_name} ->
        {:precompiled,
         "https://github.com/membraneframework-precompiled/precompiled_libnice/releases/latest/download/libnice_macos_arm.tar.gz"}

      _other ->
        nil
    end
  end

  defp natives() do
    [
      native: [
        sources: ["native.c", "parser.c"],
        deps: [unifex: :unifex],
        os_deps: [{get_libnice_url(), "nice"}],
        interface: [:nif, :cnode],
        preprocessor: Unifex
      ]
    ]
  end
end
