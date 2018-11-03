# MultiBungeeGlue

The database-free glue for multi-BungeeCord networks.

**Note:** MultiBungeeGlue is still in development, which means there is very verbose logging, including stack traces of irrelevant exceptions.

- [Download](https://raw.githubusercontent.com/timmyrs/MultiBungeeGlue/master/MultiBungeeGlue.jar)

## Installation

For each BungeeCord server:

1. Remove `cmd_alert` and `cmd_send` from the `modules.yml`.
2. Remove the `cmd_alert.jar` and `cmd_send.jar` from the `modules/` folder.
3. Move the `MultiBungeeGlue.jar` into the `plugins/` folder.
4. Restart BungeeCord.
5. Edit the `plugins/MultiBungeeGlue/config.yml`.
6. Restart BungeeCord again.

## Permissions

Permission | Description
-----------|-----------
`multibungeeglue.command.alert` | Allows the player to execute `/alert`.
`multibungeeglue.command.endall` | Allows the player to execute `/endall`.
`multibungeeglue.command.lobby` | Allows the player to execute `/lobby` and `/hub`.
`multibungeeglue.command.send` | Allows the player to execute `/send`.

## Commands

### `/alert <message>`

Sends an alert to every player.

### `/endall`

Stops all BungeeCord servers. This is useful if you have a loop script to effectively restart them all in one command.

### `/lobby`

**Alias:** `/hub`

Connects the player to the lobby server as defined by `lobby` in the `config.yml`.

### `/send <all|server|player> <target server>`

Sends every player, or everyone on `server`, or the player `player` to `target server`.
