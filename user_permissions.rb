require 'set'

class UserPermissions

  def initialize(user, cm_invoice)
    @user = user
    @cm_invoice = cm_invoice
  end

  def get_permissions
    get_user_permissions + get_cm_invoice_user_permissions
  end

  #  returns permissions if user is set in security context   */
  def get_user_permissions
    user_permissions = Set.new
    if (@user != nil)
      user_permissions << :DEFAULT_PERMISSION
      add_permissions_based_on_rule(:CM_TEAM_ROLE_PERMISSION, has_cm_team_role, user_permissions)
      add_permissions_based_on_rule(:FINANCE_INVOICE_PERMISSION, has_invoice_finance_role, user_permissions)
      if (has_cm_invoice_view_role || has_invoice_finance_role)
        user_permissions << :CM_INVOICE_USER_PERMISSION
        user_permissions << :INVOICE_VIEW_PERMISSION
        user_permissions << :ACCESS_ALL_INVOICE_PERMISSION
      end
      add_permissions_based_on_rule(:CM_INVOICE_USER_PERMISSION, has_application_access(nil), user_permissions)
      add_application_access_permissions_for_roles(user_permissions)
    end
    user_permissions
  end

  def add_application_access_permissions_for_roles user_permissions
    {:CM_INVOICE_ROLE => :CM_ANY_INVOICE_PERMISSION,
     :PA_INVOICE_ROLE => :PA_ANY_INVOICE_PERMISSION,
     :SDT_INVOICE_ROLE => :SDT_ANY_INVOICE_PERMISSION}.each do |role, permission|
      add_permissions_based_on_rule(permission, has_application_access(role), user_permissions)
    end
  end

  def add_permissions_based_on_rule permission, rule, user_permissions
    user_permissions << permission if rule
  end

  # permissions granted in context of an invoice and a user
  def get_cm_invoice_user_permissions
    invoice_permissions = Set.new
    if (@cm_invoice)
      if (has_read_access) 
        invoice_permissions << :INVOICE_VIEW_PERMISSION
      end
      if (has_edit_access) 
        invoice_permissions << :COMMENT_ADD_PERMISSION
      end
      if (has_cm_invoice_close_right) 
        invoice_permissions << :INVOICE_CLOSE_PERMISSION
      end
      if (has_approve_access)
        invoice_permissions << :INVOICE_APPROVE_PERMISSION
      end
      if (has_reject_access)
        invoice_permissions << :INVOICE_REJECT_PERMISSION
      end
      if (has_configure_rules_access)
        invoice_permissions << :CONFIGURE_RULES_PERMISSION
      end
      if (has_view_rules_access) 
        invoice_permissions << :VIEW_RULES_PERMISSION
      end
      if (has_cm_edit_access) 
        approval_status = @cm_invoice.approval_status
        if (cm_invoice_editable?(approval_status)) 
          invoice_permissions << :CM_EDIT_SETUP_PERMISSION
        end
        if (approval_status == :CM_STATUS) 
          invoice_permissions << :CM_BILLING_PERIOD_EDIT_PERMISSION
          if (@cm_invoice.in_transition?)
            invoice_permissions << :CM_EDIT_BILLING_PERIOD_TRANSITION_PERMISSION
          end
        end
        if (can_add_billing_period?(approval_status))
          invoice_permissions << :CM_BILLING_PERIOD_ADD_PERMISSION
        end
      end
      if (has_invoice_log_access)
        invoice_permissions << :INVOICE_LOG_PERMISSION
      end
    end
    invoice_permissions
  end

  def cm_invoice_editable?(approval_status)
    [:NEW_STATUS, :CM_STATUS].include? approval_status
  end

  def can_add_billing_period?(approval_status)
    [:APPROVED_STATUS, :NEW_STATUS].include? approval_status
  end

end
