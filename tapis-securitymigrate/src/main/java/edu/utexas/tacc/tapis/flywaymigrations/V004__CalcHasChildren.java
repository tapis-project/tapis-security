package edu.utexas.tacc.tapis.flywaymigrations;

import java.sql.PreparedStatement;

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

/** When migrating an existing database after the introduction of the 
 * has_children flag in role records, we need to set the flag on roles
 * that do have children.
 * 
 * @author rcardone
 */
final public class V004__CalcHasChildren
 extends BaseJavaMigration
{
	@Override
	public void migrate(Context context) throws Exception 
	{
		// Announcement.
		System.out.println("V004__CalcHasChildren starting.");
		
		// Set autocommit off.
		var conn = context.getConnection();
		conn.setAutoCommit(false);
		
		// Construct the update command that properly set the has_children flag
		// from the default (false) to true when existing roles have children.
		// If the subquery returns no parent roles then the update has no effect.
		final String sql = 
			"UPDATE sk_role SET has_children = ? " + 
			"WHERE id IN (SELECT DISTINCT parent_role_id FROM sk_role_tree)";
		
		// Issue the update.
		PreparedStatement pstmt = conn.prepareStatement(sql);
		pstmt.setBoolean(1, true);
        int rows = pstmt.executeUpdate();

        // Commit the transaction.
        pstmt.close();
        conn.commit();
        
        // Result message.
        System.out.println("V004__CalcHasChildren: " + rows + " updated.");
	}
}
