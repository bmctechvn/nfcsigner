package com.bmc.nfcsigner.core

class DebugLogger(private val tag: String) {

    companion object {
        const val DEBUG_USB = false
    }

    fun debug(message: String) {
        if (DEBUG_USB) {
            println("[$tag] $message")
        }
    }
}