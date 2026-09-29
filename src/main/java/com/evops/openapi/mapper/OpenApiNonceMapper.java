package com.evops.openapi.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.evops.openapi.nonce.OpenApiNonce;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface OpenApiNonceMapper extends BaseMapper<OpenApiNonce> {
}
