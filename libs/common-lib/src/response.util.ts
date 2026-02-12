export function apiResponse(
  message: string,
  data: any = null,
  meta: any = null,
) {
  return {
    message,
    data,
    ...(meta ? { meta } : {}),
    ts: new Date().toISOString(),
  };
}
