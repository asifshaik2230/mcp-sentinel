package com.mcpsentinel.proxy.repository;

import com.mcpsentinel.proxy.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findAllByOrderByTimestampDesc();

    long countByStatus(String status);

    @Query("SELECT COUNT(DISTINCT a.sessionId) FROM AuditLog a WHERE a.sessionId IS NOT NULL AND a.sessionId <> ''")
    long countDistinctSessions();
}
