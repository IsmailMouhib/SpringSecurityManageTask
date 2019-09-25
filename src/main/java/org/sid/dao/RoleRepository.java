package org.sid.dao;

import org.sid.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<AppRole, Long> {

    AppRole findByRoleName(String roleName);
}
