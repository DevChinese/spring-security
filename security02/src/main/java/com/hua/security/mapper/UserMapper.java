package com.hua.security.mapper;

import com.hua.security.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Mapper
@Repository
public interface UserMapper {
    User selectByUsername(String username);
}
