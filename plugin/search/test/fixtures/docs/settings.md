Settings precedence determines which value wins when the same key is set in
more than one place. From highest to lowest priority: managed policy
settings, command-line flags, local project settings, shared project
settings, and finally user settings. A value set at a higher level always
overrides one set at a lower level, and this order never changes based on
which file was edited most recently.
