use super::OnnxProviderPolicy;

pub(super) struct CudaDropGuard<T> {
    value: Option<T>,
    bound_stream: Option<super::green_context::GreenContextHandle>,
    leak_on_drop: bool,
}

impl<T> CudaDropGuard<T> {
    pub(super) fn new(value: T, provider_policy: OnnxProviderPolicy) -> Self {
        Self {
            value: Some(value),
            bound_stream: None,
            leak_on_drop: provider_policy == OnnxProviderPolicy::CudaFailLoud,
        }
    }

    pub(super) fn with_bound_stream(
        mut self,
        bound_stream: Option<super::green_context::GreenContextHandle>,
    ) -> Self {
        self.bound_stream = bound_stream;
        self
    }

    pub(super) fn bound_stream(&self) -> Option<&super::green_context::GreenContextHandle> {
        self.bound_stream.as_ref()
    }

    pub(super) fn as_ref(&self) -> &T {
        self.value
            .as_ref()
            .expect("CudaDropGuard value is present until into_inner")
    }

    pub(super) fn into_inner(mut self) -> T {
        debug_assert!(
            self.bound_stream.is_none(),
            "use CudaDropGuard::into_parts when an external CUDA stream is bound"
        );
        self.value
            .take()
            .expect("CudaDropGuard value is present until into_inner")
    }

    pub(super) fn into_parts(mut self) -> (T, Option<super::green_context::GreenContextHandle>) {
        let value = self
            .value
            .take()
            .expect("CudaDropGuard value is present until into_parts");
        (value, self.bound_stream.take())
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
            let bound_stream = self.bound_stream.take();
            std::mem::forget((value, bound_stream));
        }
    }
}
