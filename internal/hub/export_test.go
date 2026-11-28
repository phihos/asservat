package hub

import "context"

// ForgetApprovals leaves the cluster's captures as a hub from before the
// list of approvals left them: with an approver, and no list.
func (s *Store) ForgetApprovals(ctx context.Context, cluster string) error {
	_, err := s.db.Exec(ctx, `UPDATE captures SET approvals = '{}' WHERE cluster = $1`, cluster)
	return err
}
