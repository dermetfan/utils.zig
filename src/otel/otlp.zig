pub const collector = struct {
    pub const trace = @import("otlp/opentelemetry/proto/collector/trace/v1.pb.zig");
};
pub const common = @import("otlp/opentelemetry/proto/common/v1.pb.zig");
pub const resource = @import("otlp/opentelemetry/proto/resource/v1.pb.zig");
pub const trace = @import("otlp/opentelemetry/proto/trace/v1.pb.zig");
