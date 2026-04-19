/*
 * Copyright (c) 2026 Paralino
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
    versionCatalogs {
        defaultLibrariesExtensionName = "parasodiumlibs"
        create("parasodiumlibs") {
            from(files("gradle/parasodiumlibs.versions.toml"))
        }
    }
}

rootProject.name = "Parasodium"

include(":parasodium")
