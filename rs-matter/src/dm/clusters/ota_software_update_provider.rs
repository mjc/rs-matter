//! Native handler for the Matter OTA Software Update Provider cluster.

use crate::dm::{Cluster, Dataver, InvokeContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::Octets;
use crate::tlv::TLVBuilderParent;
use crate::with;

pub use crate::dm::clusters::decl::ota_software_update_provider::*;

/// Maximum values defined by the Matter 1.4.2 OTA Software Update Provider IDL.
pub const MAX_IMAGE_URI_LEN: usize = 256;
pub const MAX_SOFTWARE_VERSION_STRING_LEN: usize = 64;
pub const MAX_UPDATE_TOKEN_LEN: usize = 32;
pub const MAX_REQUESTOR_METADATA_LEN: usize = 512;

/// Device and image identity constraints applied before an image is offered.
#[derive(Clone, Copy, Debug)]
pub struct ImagePolicy {
    pub vendor_id: u16,
    pub product_id: u16,
    pub software_version: u32,
    pub min_hardware_version: Option<u16>,
    pub max_hardware_version: Option<u16>,
}

impl ImagePolicy {
    /// Returns whether this image is newer and targets the requesting device.
    pub fn matches(
        &self,
        vendor_id: u16,
        product_id: u16,
        current_version: u32,
        hardware_version: Option<u16>,
    ) -> bool {
        vendor_id == self.vendor_id
            && product_id == self.product_id
            && current_version < self.software_version
            && match (
                self.min_hardware_version,
                self.max_hardware_version,
                hardware_version,
            ) {
                (None, None, _) => true,
                (min, max, Some(version)) => {
                    min.is_none_or(|min| version >= min) && max.is_none_or(|max| version <= max)
                }
                _ => false,
            }
    }
}

/// An image the provider can offer to matching requestors.
#[derive(Clone, Copy, Debug)]
pub struct OtaImage<'a> {
    pub policy: ImagePolicy,
    pub image_uri: &'a str,
    pub software_version_string: &'a str,
    pub update_token: &'a [u8],
    pub metadata_for_requestor: Option<&'a [u8]>,
    pub protocols: &'a [DownloadProtocolEnum],
}

/// A small, reusable handler for one currently available image.
#[derive(Clone, Debug)]
pub struct OtaSoftwareUpdateProviderHandler<'a> {
    dataver: Dataver,
    image: Option<OtaImage<'a>>,
}

impl<'a> OtaSoftwareUpdateProviderHandler<'a> {
    pub const fn new(dataver: Dataver, image: Option<OtaImage<'a>>) -> Self {
        Self { dataver, image }
    }

    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    fn token_matches(&self, token: &[u8], version: u32) -> bool {
        self.image.is_some_and(|image| {
            image.policy.software_version == version
                && image.update_token == token
                && !token.is_empty()
                && token.len() <= MAX_UPDATE_TOKEN_LEN
        })
    }

    fn apply_action(&self, token: &[u8], version: u32) -> ApplyUpdateActionEnum {
        if self.token_matches(token, version) {
            ApplyUpdateActionEnum::Proceed
        } else {
            ApplyUpdateActionEnum::Discontinue
        }
    }

    fn image_is_encodable(image: OtaImage<'_>) -> bool {
        !image.image_uri.is_empty()
            && image.image_uri.len() <= MAX_IMAGE_URI_LEN
            && image.software_version_string.len() <= MAX_SOFTWARE_VERSION_STRING_LEN
            && !image.update_token.is_empty()
            && image.update_token.len() <= MAX_UPDATE_TOKEN_LEN
            && image
                .metadata_for_requestor
                .is_none_or(|metadata| metadata.len() <= MAX_REQUESTOR_METADATA_LEN)
    }
}

impl ClusterHandler for OtaSoftwareUpdateProviderHandler<'_> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required)).with_cmds(with!(
        CommandId::QueryImage | CommandId::ApplyUpdateRequest | CommandId::NotifyUpdateApplied
    ));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn handle_query_image<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: QueryImageRequest<'_>,
        response: QueryImageResponseBuilder<P>,
    ) -> Result<P, Error> {
        let Some(image) = self.image else {
            return response
                .status(StatusEnum::NotAvailable)?
                .delayed_action_time(None)?
                .image_uri(None)?
                .software_version(None)?
                .software_version_string(None)?
                .update_token(None)?
                .user_consent_needed(None)?
                .metadata_for_requestor(None)?
                .end();
        };

        if !Self::image_is_encodable(image) {
            return response
                .status(StatusEnum::NotAvailable)?
                .delayed_action_time(None)?
                .image_uri(None)?
                .software_version(None)?
                .software_version_string(None)?
                .update_token(None)?
                .user_consent_needed(None)?
                .metadata_for_requestor(None)?
                .end();
        }

        if !image.policy.matches(
            request.vendor_id()?,
            request.product_id()?,
            request.software_version()?,
            request.hardware_version()?,
        ) {
            return response
                .status(StatusEnum::NotAvailable)?
                .delayed_action_time(None)?
                .image_uri(None)?
                .software_version(None)?
                .software_version_string(None)?
                .update_token(None)?
                .user_consent_needed(None)?
                .metadata_for_requestor(None)?
                .end();
        }

        let protocols = request.protocols_supported()?;
        if !image.protocols.iter().any(|supported| {
            protocols
                .iter()
                .any(|requested| requested.is_ok_and(|protocol| protocol == *supported))
        }) {
            return response
                .status(StatusEnum::DownloadProtocolNotSupported)?
                .delayed_action_time(None)?
                .image_uri(None)?
                .software_version(None)?
                .software_version_string(None)?
                .update_token(None)?
                .user_consent_needed(None)?
                .metadata_for_requestor(None)?
                .end();
        }

        response
            .status(StatusEnum::UpdateAvailable)?
            .delayed_action_time(None)?
            .image_uri(Some(image.image_uri))?
            .software_version(Some(image.policy.software_version))?
            .software_version_string(Some(image.software_version_string))?
            .update_token(Some(Octets::new(image.update_token)))?
            .user_consent_needed(None)?
            .metadata_for_requestor(image.metadata_for_requestor.map(Octets::new))?
            .end()
    }

    fn handle_apply_update_request<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: ApplyUpdateRequestRequest<'_>,
        response: ApplyUpdateResponseBuilder<P>,
    ) -> Result<P, Error> {
        let action = self.apply_action(request.update_token()?.0, request.new_version()?);
        response.action(action)?.delayed_action_time(0)?.end()
    }

    fn handle_notify_update_applied(
        &self,
        _ctx: impl InvokeContext,
        request: NotifyUpdateAppliedRequest<'_>,
    ) -> Result<(), Error> {
        if !self.token_matches(request.update_token()?.0, request.software_version()?) {
            return Err(ErrorCode::InvalidAction.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApplyUpdateActionEnum, Dataver, DownloadProtocolEnum, ImagePolicy, OtaImage,
        OtaSoftwareUpdateProviderHandler, MAX_IMAGE_URI_LEN, MAX_REQUESTOR_METADATA_LEN,
        MAX_SOFTWARE_VERSION_STRING_LEN, MAX_UPDATE_TOKEN_LEN,
    };

    #[test]
    fn image_policy_requires_matching_device_and_newer_version() {
        let policy = ImagePolicy {
            vendor_id: 0x1234,
            product_id: 0x5678,
            software_version: 12,
            min_hardware_version: Some(2),
            max_hardware_version: Some(4),
        };

        assert!(policy.matches(0x1234, 0x5678, 11, Some(3)));
        assert!(!policy.matches(0x1234, 0x5678, 12, Some(3)));
        assert!(!policy.matches(0x9999, 0x5678, 11, Some(3)));
        assert!(!policy.matches(0x1234, 0x5678, 11, Some(1)));
        assert!(!policy.matches(0x1234, 0x5678, 11, Some(5)));
    }

    #[test]
    fn hardware_policy_requires_a_reported_hardware_version_when_bounded() {
        let policy = ImagePolicy {
            vendor_id: 1,
            product_id: 2,
            software_version: 3,
            min_hardware_version: Some(1),
            max_hardware_version: None,
        };

        assert!(!policy.matches(1, 2, 2, None));
        assert!(policy.matches(1, 2, 2, Some(1)));
        assert!(policy.matches(1, 2, 2, Some(u16::MAX)));
    }

    fn image<'a>(
        uri: &'a str,
        version_string: &'a str,
        token: &'a [u8],
        metadata: Option<&'a [u8]>,
    ) -> OtaImage<'a> {
        OtaImage {
            policy: ImagePolicy {
                vendor_id: 1,
                product_id: 2,
                software_version: 3,
                min_hardware_version: None,
                max_hardware_version: None,
            },
            image_uri: uri,
            software_version_string: version_string,
            update_token: token,
            metadata_for_requestor: metadata,
            protocols: &[DownloadProtocolEnum::HTTPS],
        }
    }

    #[test]
    fn image_is_rejected_when_response_fields_exceed_idl_limits() {
        let valid = image("https://host/image.ota", "3", b"token", Some(b"meta"));
        assert!(OtaSoftwareUpdateProviderHandler::image_is_encodable(valid));

        assert!(!OtaSoftwareUpdateProviderHandler::image_is_encodable(
            image(&"u".repeat(MAX_IMAGE_URI_LEN + 1), "3", b"token", None)
        ));
        assert!(!OtaSoftwareUpdateProviderHandler::image_is_encodable(
            image(
                "https://host/image.ota",
                &"v".repeat(MAX_SOFTWARE_VERSION_STRING_LEN + 1),
                b"token",
                None
            )
        ));
        assert!(!OtaSoftwareUpdateProviderHandler::image_is_encodable(
            image(
                "https://host/image.ota",
                "3",
                &vec![0; MAX_UPDATE_TOKEN_LEN + 1],
                None
            )
        ));
        assert!(!OtaSoftwareUpdateProviderHandler::image_is_encodable(
            image(
                "https://host/image.ota",
                "3",
                b"token",
                Some(&vec![0; MAX_REQUESTOR_METADATA_LEN + 1])
            )
        ));
        assert!(!OtaSoftwareUpdateProviderHandler::image_is_encodable(
            image("", "3", b"token", None)
        ));
    }

    #[test]
    fn apply_action_requires_exact_token_and_advertised_version() {
        let image = image("https://host/image.ota", "3", b"opaque token", None);
        let handler = OtaSoftwareUpdateProviderHandler::new(Dataver::new(0), Some(image));

        assert_eq!(
            handler.apply_action(b"opaque token", 3),
            ApplyUpdateActionEnum::Proceed
        );
        assert_eq!(
            handler.apply_action(b"wrong token", 3),
            ApplyUpdateActionEnum::Discontinue
        );
        assert_eq!(
            handler.apply_action(b"opaque token", 4),
            ApplyUpdateActionEnum::Discontinue
        );
        assert_eq!(
            handler.apply_action(&[], 3),
            ApplyUpdateActionEnum::Discontinue
        );
        assert_eq!(
            handler.apply_action(&vec![0; MAX_UPDATE_TOKEN_LEN + 1], 3),
            ApplyUpdateActionEnum::Discontinue
        );
    }
}
