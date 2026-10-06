# hermes-plugin-tirith

[tirith](https://github.com/sheeki03/tirith) command scanning for [Hermes Agent](https://github.com/NousResearch/hermes-agent), as an opt-in plugin.

**Status: not ready yet. Nothing here can be installed today.**

Hermes is removing its built-in tirith integration ([NousResearch/hermes-agent#133832](https://github.com/NousResearch/hermes-agent/pull/133832)). This repo will hold the replacement: a `pre_tool_call` hook that runs your locally installed `tirith` on each terminal command and sends any finding to Hermes's normal approval prompt.

It will need a tirith release that is still in progress. Once the plugin is published and listed in the Hermes plugin catalog, you will be able to install it with:

```
hermes plugins install tirith
```

Progress is tracked in [sheeki03/tirith#272](https://github.com/sheeki03/tirith/issues/272).
