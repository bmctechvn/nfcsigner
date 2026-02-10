package com.bmc.nfcsigner.core

class DebugLogger(private val tag: String) {

    companion object {
        const val DEBUG_USB = true
    }

    fun debug(message: String) {
        if (DEBUG_USB) {
            println("[$tag] $message")
        }
    }
}