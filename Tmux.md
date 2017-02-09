# Tmux



## General



| Shortcut   | Description                    |
| ---------- | ------------------------------ |
| <PREFIX> : | enter command mode             |
| <PREFIX> ? | show all bindings and commands |



## Copy & Paste



| Shortcut   | Description            |
| ---------- | ---------------------- |
| <PREFIX> [ | enter copy mode        |
| <PREFIX> ] | paste buffers          |
| <PREFIX> = | list all paste buffers |



## Command mode

Commands can be prefixed with tmux on command line and using "-t" switch manipulate a tmux session from the outside too.

```bash
tmux split-window -t <session-name>
```

send keystrokes to session by using "send-keys"

```bash
tmux send-keys -t <session-name> 'vim' C-m
```

"C-m" carriage return

to send to specific panes:

```bash
tmux send-keys -t <session-name>:<window number>.<pane number>  <command> C-m
```



Commands can be seperated by ;

| Command                                  | Description                             |
| ---------------------------------------- | --------------------------------------- |
| source-file <PATH>                       | reload config file                      |
| display <string>                         | basic output function for status line   |
| show options -g                          | show global options                     |
| show options -w                          | show window options                     |
| join-pane -s <session  name>:<window number> | join window from session.window to pane |
| set-window-option synchronize-panes on/off | write into all panes at the same time   |

## Session management

Starting a new session

```bash
tmux new -s <name>
```

list sessions

```bash
tmux ls
```

attaching (single session)

```bash
tmux attach
```

attaching named session

```bash
tmux attach -t <name>
```

killing sessions

```bash
tmux kill-session -t <name>
```



| Shortcut   | Description                              |
| ---------- | ---------------------------------------- |
| <PREFIX> t | show clock                               |
| <PREFIX> d | detach                                   |
| <PREFIX> ( | previous session                         |
| <PREFIX> ) | next session                             |
| <PREFIX> s | display open sessions (space to expand sessions) |
| <PREFIX> . | move window to other session             |



## Window management

| Shortcut          | Description                |
| ----------------- | -------------------------- |
| <PREFIX> c        | new window (create)        |
| <PREFIX> ,        | rename window              |
| <PREFIX> n        | (n)ext window              |
| <PREFIX> p        | (p)revious window          |
| <PREFIX> <number> | jump to window with number |
| <PREFIX> w        | show window menu           |
| <PREFIX> &        | close window               |
| <PREFIX> !        | create a window from pane  |



## Pane management

| Shortcut                  | Description                              |
| ------------------------- | ---------------------------------------- |
| <PREFIX> %                | split vertical                           |
| <PREFIX> "                | split horizontal                         |
| <PREFIX> o                | cycle through panes                      |
| <PREFIX> <cursor buttons> | navigate through panes                   |
| <PREFIX> space            | cycle through pane layouts (even-horizontal, even-vertical, main-horizontal, main-vertical, tiled) |
| <PREFIX> x                | exit pane                                |
| <PREFIX> z                | zoom in to current pane                  |

## tmux.conf

```
set -g status-style "fg=white,bold,bg=black"
set -g window-status-style "fg=cyan,bold,bg=black"

set -g base-index 1
set -g pane-base-index 1

setw -g window-status-current-style "fg=white,bg=cyan"
setw -g pane-border-style "fg=green,bg=black"
setw -g pane-active-border-style "fg=white,bg=yellow"

setw -g window-style "fg=colour240,bg=colour235"
setw -g window-active-style "fg=white,bg=black"

setw -g mode-keys vi
bind Escape copy-mode
bind -t vi-copy 'v' begin-selection
bind -t vi-copy 'y' copy-selection
unbind p
bind p paste-buffer

bind h select-pane -L
bind n select-pane -D
bind e select-pane -U
bind i select-pane -R

bind -r H resize-pane -L 5
bind -r N resize-pane -D 5
bind -r E resize-pane -U 5
bind -r I resize-pane -R 5
```

