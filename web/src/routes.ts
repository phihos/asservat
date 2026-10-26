const capturePath = /^\/captures\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
export const captureIDFromPath = (path: string) => capturePath.exec(path)?.[1];
const casePath = /^\/cases\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
export const caseIDFromPath = (path: string) => casePath.exec(path)?.[1];
export function returnPath(path: string): string {
  return path === '/captures/new' || path === '/policies' || path === '/shares' || path === '/access-preview' || path === '/retention-preview' || captureIDFromPath(path) || caseIDFromPath(path) ? path : '/';
}
