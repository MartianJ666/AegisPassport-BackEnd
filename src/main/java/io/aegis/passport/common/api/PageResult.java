package io.aegis.passport.common.api;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.Page;

/**
 * Slim pagination wrapper so we never leak Spring Data's {@code Page} shape
 * (with its many internal fields) across the API boundary.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PageResult<T> {

    private List<T> items;
    private long total;
    private int page;
    private int size;

    public static <T> PageResult<T> of(Page<T> page) {
        return new PageResult<>(page.getContent(), page.getTotalElements(),
                page.getNumber(), page.getSize());
    }

    public static <T> PageResult<T> of(List<T> items, Page<?> source) {
        return new PageResult<>(items, source.getTotalElements(),
                source.getNumber(), source.getSize());
    }
}
