/* Licensed under Apache 2.0 (C) 2023 Firezone, Inc. */
package dev.firezone.android.features.applink.ui

import android.content.Intent
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.firezone.android.core.domain.preference.SaveTokenUseCase
import dev.firezone.android.core.domain.preference.ValidateCsrfTokenUseCase
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
internal class AppLinkViewModel
    @Inject
    constructor(
        private val validateCsrfTokenUseCase: ValidateCsrfTokenUseCase,
        private val saveTokenUseCase: SaveTokenUseCase,
    ) : ViewModel() {
        private val actionMutableLiveData = MutableLiveData<ViewAction>()
        val actionLiveData: LiveData<ViewAction> = actionMutableLiveData

        fun parseAppLink(intent: Intent) {
            Log.d("AppLinkViewModel", "Parsing app link...")
            viewModelScope.launch {
                Log.d("AppLinkViewModel", "viewmodelScope.launch")
                when (intent.data?.lastPathSegment) {
                    PATH_CALLBACK -> {
                        Log.d("AppLinkViewModel", "PATH_CALLBACK")
                        intent.data?.getQueryParameter(QUERY_CLIENT_CSRF_TOKEN)?.let { csrfToken ->
                            Log.d("AppLinkViewModel", "csrfToken: $csrfToken")
                            if (validateCsrfTokenUseCase(csrfToken).firstOrNull() == true) {
                                Log.d("AppLinkViewModel", "Valid CSRF token. Continuing to save token...")
                            } else {
                                Log.d("AppLinkViewModel", "Invalid CSRF token! Continuing to save token anyway...")
                            }
                            intent.data?.getQueryParameter(QUERY_CLIENT_AUTH_TOKEN)?.let { token ->
                                if (token.isNotBlank()) {
                                    Log.d("AppLinkViewModel", "Found valid auth token in response")
                                    saveTokenUseCase(token).collect()
                                } else {
                                    Log.d("AppLinkViewModel", "Didn't find auth token in response!")
                                }
                            }

                            actionMutableLiveData.postValue(ViewAction.AuthFlowComplete)
                        }
                    }
                    else -> {
                        Log.d("AppLinkViewModel", "Unknown path segment: ${intent.data?.lastPathSegment}")
                    }
                }
            }
        }

        companion object {
            private const val PATH_CALLBACK = "handle_client_sign_in_callback"
            private const val QUERY_CLIENT_CSRF_TOKEN = "client_csrf_token"
            private const val QUERY_CLIENT_AUTH_TOKEN = "client_auth_token"
            private const val QUERY_ACTOR_NAME = "actor_name"
            private const val QUERY_IDENTITY_PROVIDER_IDENTIFIER = "identity_provider_identifier"
        }

        internal sealed class ViewAction {
            object AuthFlowComplete : ViewAction()

            object ShowError : ViewAction()
        }
    }
