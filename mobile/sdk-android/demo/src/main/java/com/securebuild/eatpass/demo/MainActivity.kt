package com.securebuild.eatpass.demo

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securebuild.eatpass.EatPassConfig
import com.securebuild.eatpass.EatPassMobileClient
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val attester = findViewById<EditText>(R.id.attesterUrl)
        val issuer = findViewById<EditText>(R.id.issuerUrl)
        val output = findViewById<TextView>(R.id.output)
        val mint = findViewById<Button>(R.id.mint)

        attester.setText("http://10.0.2.2:8087")
        issuer.setText("http://10.0.2.2:8088")

        mint.setOnClickListener {
            output.text = "Minting…"
            lifecycleScope.launch {
                runCatching {
                    val client = EatPassMobileClient(
                        applicationContext,
                        EatPassConfig(
                            attesterUrl = attester.text.toString(),
                            issuerUrl = issuer.text.toString(),
                        ),
                    )
                    client.mintAuthorizationHeader()
                }.onSuccess { result ->
                    output.text = "OK\n${result.authorizationHeader.take(80)}…"
                }.onFailure { e ->
                    output.text = "Error: ${e.message}"
                }
            }
        }
    }
}
