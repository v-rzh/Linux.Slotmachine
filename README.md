# Linux.Slotmachine

```
        |     . |                   |    o
   ,---.|    / \|--- ,-.-.,---.,---.|---..,---.,---.
   `---.|       |    | | |,---||    |   |||   ||---'
   `---'`---'   `---'` ' '`---^`---'`   '``   '`---'
```
  
Linux.Slotmachine is a metamorphic ELF virus.

This repo is meant to supplement articles and generated virus source code in
tmpout #4.

## Building

The first stage of the virus is built with the GNU toolchain.
The morph table generator depends on
[Keystone](https://www.keystone-engine.org/docs/) and
[Capstone](https://www.capstone-engine.org/documentation.html) libraries,
which must be installed on the system in order for the build script to
work out of the box. Please refer to the linked docs for instructions.

When you run `make` a plain version of the virus will be compiled, then
the morph table generator will be built and ran against the plain virus,
producing a version that will transform after each infection.

If you're experimenting with the source code I strongly advise running
`make clean` before rebuilding

## Testing
The `targets` directory has a decent number of hosts to test the virus, as
well as a few broken ELFs. Running `make run` will pop the virus and the test
binary (configured with the `TEST_BIN` variable in the `Makefile`) into the
`evolution_chamber` and after infecting the host, will run an infinite loop
replacing the infecting binary with the newly infected host, restoring the
target to the original host, running the infected host against the fresh one,
and so on.
