defmodule ExLibnice.BundlexProject do
  use Bundlex.Project

  def project do
    [
      natives: natives()
    ]
  end

  defp natives() do
    [
      native: [
        sources: ["native.c", "parser.c", "unifex_util.c"],
        deps: [unifex: :unifex],
        pkg_configs: ["nice"],
        libs: ["pthread"],
        interface: :cnode,
        preprocessor: Unifex
      ]
    ]
  end
end
