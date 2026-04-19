/*
 * Copyright (c) 2026 Paralino
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions derived from Lazysodium (Terl Tech Ltd).
 */

plugins {
    id("com.android.library")
}

android {
    namespace = "app.paralino.parasodium"
    compileSdk = parasodiumlibs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = parasodiumlibs.versions.minSdk.get().toInt()
        multiDexEnabled = true
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    sourceSets.getByName("main") {
        jniLibs.srcDirs("src/main/jniLibs")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    packaging {
        jniLibs {
            keepDebugSymbols += setOf("**/libsodium.so")
        }
    }

    testOptions {
        animationsDisabled = true
        execution = "ANDROIDX_TEST_ORCHESTRATOR"
    }
}

kotlin {
    jvmToolchain(21)
}

tasks.withType<Test>().configureEach {
    testLogging {
        events("started", "skipped", "passed", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true
    }
}

dependencies {
    implementation(parasodiumlibs.kotlin.stdlib)
    implementation(parasodiumlibs.java.jna) {
        artifact { type = "aar" }
    }
    implementation(parasodiumlibs.androidx.core.ktx)
    androidTestImplementation(parasodiumlibs.androidx.test.core)
    androidTestImplementation(parasodiumlibs.androidx.test.ext.junit)
    androidTestImplementation(parasodiumlibs.androidx.test.rules)
    androidTestImplementation(parasodiumlibs.androidx.test.runner)
    androidTestUtil(parasodiumlibs.androidx.test.orchestrator)
}
