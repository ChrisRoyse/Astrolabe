use super::OnnxProviderPolicy;

pub(super) struct CudaDropGuard<T> {
    value: Option<T>,
    leak_on_drop: bool,
}

impl<T> CudaDropGuard<T> {
    pub(super) fn new(value: T, provider_policy: OnnxProviderPolicy) -> Self {
        Self {
            value: Some(value),
            leak_on_drop: provider_policy == OnnxProviderPolicy::CudaFailLoud,
        }
    }

    pub(super) fn as_ref(&self) -> &T {
        self.value
            .as_ref()
            .expect("CudaDropGuard value is present until into_inner")
    }

    pub(super) fn into_inner(mut self) -> T {
        self.value
            .take()
            .expect("CudaDropGuard value is present until into_inner")
    }
}

impl<T> Drop for CudaDropGuard<T> {
    fn drop(&mut self) {
        if self.leak_on_drop
            && let Some(value) = self.value.take()
        {
            // ORT CUDA provider teardown can corrupt glibc heap in a manual verification run.
            // Successful lenses leak in OnnxLens::drop; this guard applies the
            // same policy to construction errors after a CUDA session exists.
            std::mem::forget(value);
        }
    }
}
