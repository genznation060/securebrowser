package com.example

import android.app.Application
import com.example.data.SecurityStorage

class SecureBrowseApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Initialize persistent security storage and default rules
        SecurityStorage.getInstance(this)
    }
}
