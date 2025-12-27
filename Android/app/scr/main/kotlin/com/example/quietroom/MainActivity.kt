package com.example.quietroom

import android.app.Activity
import android.content.Intent
import android.media.RingtoneManager
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.style.ForegroundColorSpan
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import chat.Chat // From the gomobile binding (package name 'chat')
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : AppCompatActivity() {

    private var client: Chat.Client? = null
    private lateinit var messagesText: TextView
    private lateinit var inputEdit: EditText
    private lateinit var sendButton: Button
    private lateinit var fileButton: Button
    private val messageBuilder = SpannableStringBuilder()

    // Color map for parsing Go color tags
    private val colorMap = mapOf(
        "[reset]" to android.graphics.Color.WHITE,
        "[red]" to android.graphics.Color.RED,
        "[green]" to android.graphics.Color.GREEN,
        "[yellow]" to android.graphics.Color.YELLOW,
        "[blue]" to android.graphics.Color.BLUE,
        "[magenta]" to android.graphics.Color.MAGENTA,
        "[cyan]" to android.graphics.Color.CYAN,
        "[white]" to android.graphics.Color.WHITE,
        "[gray]" to ContextCompat.getColor(this, android.R.color.darker_gray),
        "[bright_red]" to ContextCompat.getColor(this, android.R.color.holo_red_light),
        "[bright_green]" to ContextCompat.getColor(this, android.R.color.holo_green_light),
        "[bright_yellow]" to ContextCompat.getColor(this, android.R.color.holo_orange_light),
        "[bright_blue]" to ContextCompat.getColor(this, android.R.color.holo_blue_light),
        "[bright_magenta]" to ContextCompat.getColor(this, android.R.color.holo_purple),
        "[bright_cyan]" to ContextCompat.getColor(this, android.R.color.holo_blue_bright)
    )

    private val getContent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                val filePath = getPathFromUri(uri)
                if (filePath != null) {
                    // First, send the /file command (Android handles target user prompt if needed)
                    val targetUser = "target_username" // Prompt user for this in real app
                    val sendStatus = client?.send("/file $targetUser $filePath")
                    if (sendStatus != "") {
                        appendMessage(sendStatus!!)
                    } else {
                        val fileStatus = client?.sendFile(filePath)
                        if (fileStatus != "") {
                            appendMessage(fileStatus!!)
                        }
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        messagesText = findViewById(R.id.messages_text)
        inputEdit = findViewById(R.id.input_edit)
        sendButton = findViewById(R.id.send_button)
        fileButton = findViewById(R.id.file_button)

        client = Chat.newClient()

        val connectStatus = client?.connect("localhost:37842") // Use config or input for addr
        appendMessage(connectStatus!!)

        sendButton.setOnClickListener {
            val text = inputEdit.text.toString().trim()
            if (text.isNotEmpty()) {
                val status = client?.send(text)
                if (status != "") {
                    appendMessage(status!!)
                }
                inputEdit.setText("")
            }
        }

        fileButton.setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.type = "*/*"
            getContent.launch(intent)
        }

        // Listen for messages in background
        CoroutineScope(Dispatchers.IO).launch {
            val ch = client?.receive()
            while (true) {
                val msg = ch?.receive() // Blocking receive
                withContext(Dispatchers.Main) {
                    appendMessage(msg!!)
                    if (client?.config?.soundNotification == true) {
                        playNotificationSound()
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        client?.close()
        super.onDestroy()
    }

    private fun appendMessage(msg: String) {
        // Parse color tags and apply spans
        val start = messageBuilder.length
        messageBuilder.append(msg).append("\n")

        var currentIndex = 0
        while (currentIndex < msg.length) {
            val tagStart = msg.indexOf("[", currentIndex)
            if (tagStart == -1) break
            val tagEnd = msg.indexOf("]", tagStart)
            if (tagEnd == -1) break

            val tag = msg.substring(tagStart, tagEnd + 1)
            val color = colorMap[tag]
            if (color != null) {
                val textStart = start + tagEnd + 1
                val nextTag = msg.indexOf("[", tagEnd + 1)
                val textEnd = if (nextTag != -1) start + nextTag else messageBuilder.length
                messageBuilder.setSpan(ForegroundColorSpan(color), textStart, textEnd, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            currentIndex = tagEnd + 1
        }

        messagesText.text = messageBuilder
        messagesText.scrollTo(0, messagesText.height)
    }

    private fun playNotificationSound() {
        val uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
        val ringtone = RingtoneManager.getRingtone(this, uri)
        ringtone.play()
    }

    private fun getPathFromUri(uri: Uri): String? {
        val cursor = contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            if (it.moveToFirst()) {
                val idx = it.getColumnIndex("_display_name")
                if (idx != -1) {
                    val fileName = it.getString(idx)
                    val inputStream = contentResolver.openInputStream(uri)
                    val file = File(getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), fileName)
                    inputStream?.use { input ->
                        file.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }
                    return file.absolutePath
                }
            }
        }
        return null
    }
}