package org.whispersystems.signalservice.internal.push

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty

@JsonInclude(JsonInclude.Include.NON_NULL)
data class UpdateVerificationSessionRequestBody(
  @JsonProperty val captcha: String?,
  @JsonProperty val mcc: String?,
  @JsonProperty val mnc: String?
)
