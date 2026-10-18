package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.data.SecurityStorage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ExampleRobolectricTest {

    @Test
    fun readStringFromContext() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val appName = context.getString(R.string.app_name)
        assertEquals("SecureBrowse", appName)
    }

    @Test
    fun defaultAllowlistSeededOnFirstLaunch() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val storage = SecurityStorage.getInstance(context)
        val rules = storage.getRules()

        assertTrue("Default seed rules must be populated", rules.isNotEmpty())
        val domains = rules.map { it.normalizedDomain() }
        assertTrue("google.com must be in default seed", domains.contains("google.com"))
        assertTrue("wikipedia.org must be in default seed", domains.contains("wikipedia.org"))
        assertTrue("youtube.com must be in default seed", domains.contains("youtube.com"))
    }
}
