# Parasodium 🔒🧂

Minimal **libsodium** Kotlin bindings for Android (JNA), maintained for [Paralino](https://github.com/paralino/paralino).

## Acknowledgements

- **Lazysodium** - original [Android](https://github.com/terl/lazysodium-android) and [Java](https://github.com/terl/lazysodium-java) wrappers from [Terl](https://github.com/terl).
- **libsodium** - [jedisct1 / libsodium](https://github.com/jedisct1/libsodium).

## Module

**`:parasodium`** - Android library (`app.paralino.parasodium`). Include it as a Git submodule and add `implementation(project(":parasodium"))` from your Gradle settings (point the included project at `parasodium/` in this tree).

## Contributing

Since this project is specifically targeted at Paralino there are no plans to extend support for additional bindings or platforms.

---

Created by [Paralino](https://github.com/paralino) & [zlmr](https://github.com/zlmr)